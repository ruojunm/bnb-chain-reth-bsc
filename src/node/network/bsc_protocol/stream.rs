use alloy_primitives::bytes::BytesMut;
use alloy_rlp::{Decodable, Encodable};
use futures::{Stream, StreamExt};
use std::{pin::Pin, task::{Context, Poll, ready}};
use reth_eth_wire::multiplex::ProtocolConnection;
use bytes::Bytes;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio::time::{Duration, Sleep};
use futures::Future;

/// Handshake timeout, mirroring the Go implementation.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

use crate::node::network::votes::{VotesPacket, BscCapPacket, handle_votes_broadcast};
use super::protocol::proto::{BscProtoMessageId, BSC_PROTOCOL_VERSION};

/// Commands that can be sent to the BSC connection.
#[allow(dead_code)]
#[derive(Debug)]
pub enum BscCommand {
    SendCapability { protocol_version: u64, extra: Bytes },
    SendVotes(Vec<crate::consensus::parlia::vote::VoteEnvelope>),
}

/// Stream that handles incoming BSC protocol messages and returns outgoing messages to send.
pub struct BscProtocolConnection {
    conn: ProtocolConnection,
    commands: UnboundedReceiverStream<BscCommand>,
    handshake_deadline: Option<std::pin::Pin<Box<Sleep>>>,
    handshake_completed: bool,
    is_dialer: bool,
    initial_capability: Option<BscCommand>,
}

impl BscProtocolConnection {
    pub fn new(conn: ProtocolConnection, commands: UnboundedReceiver<BscCommand>, is_dialer: bool) -> Self {
        let handshake_deadline = Some(Box::pin(tokio::time::sleep(HANDSHAKE_TIMEOUT)));
        let initial_capability = if is_dialer {
            Some(BscCommand::SendCapability { 
                protocol_version: BSC_PROTOCOL_VERSION, 
                extra: Bytes::new() 
            })
        } else {
            None
        };
        
        Self { 
            conn, 
            commands: UnboundedReceiverStream::new(commands), 
            handshake_deadline, 
            handshake_completed: false,
            is_dialer,
            initial_capability,
        }
    }

    fn encode_command(cmd: BscCommand) -> BytesMut {
        match cmd {
            BscCommand::SendCapability { protocol_version, extra } => {
                let mut buf = BytesMut::new();
                BscCapPacket { protocol_version, extra }.encode(&mut buf);
                buf
            }
            BscCommand::SendVotes(votes) => {
                let mut buf = BytesMut::new();
                VotesPacket(votes).encode(&mut buf);
                buf
            }
        }
    }

    /// Poll for outgoing commands and encode them
    fn poll_outgoing_commands(&mut self, cx: &mut Context<'_>) -> Option<BytesMut> {
        tracing::trace!(target: "bsc_protocol", "Checking for outgoing commands");
        if let Poll::Ready(Some(cmd)) = self.commands.poll_next_unpin(cx) {
            tracing::debug!(target: "bsc_protocol", cmd = ?cmd, "Processing outgoing command");
            let encoded = Self::encode_command(cmd);
            tracing::debug!(target: "bsc_protocol", len = encoded.len(), "Sending encoded command");
            Some(encoded)
        } else {
            tracing::trace!(target: "bsc_protocol", "No outgoing commands ready");
            None
        }
    }

    /// Poll for incoming frames from the peer
    fn poll_incoming_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Option<BytesMut>>> {
        tracing::trace!(target: "bsc_protocol", "Polling for incoming frames");
        let Some(raw) = ready!(self.conn.poll_next_unpin(cx)) else {
            tracing::debug!(target: "bsc_protocol", "Connection closed by peer");
            return Poll::Ready(None);
        };

        if raw.is_empty() {
            tracing::trace!(target: "bsc_protocol", "Received empty frame");
            return Poll::Ready(Some(None));
        }

        tracing::trace!(target: "bsc_protocol", len = raw.len(), "Received frame");
        Poll::Ready(Some(Some(raw)))
    }

    /// Handle handshake-related frames
    fn handle_handshake_frame(&mut self, frame: &BytesMut, cx: &mut Context<'_>) -> Poll<Option<Option<BytesMut>>> {
        tracing::debug!(target: "bsc_protocol", "Handshake not completed, processing handshake frame");
        // Check for handshake timeout
        if let Some(deadline) = self.handshake_deadline.as_mut() {
            if Future::poll(deadline.as_mut(), cx).is_ready() {
                tracing::warn!(target: "bsc_protocol", "BSC handshake timed out");
                return Poll::Ready(None);
            }
        }

        let slice = frame.as_ref();
        let msg_id = slice[0];

        if msg_id != BscProtoMessageId::Capability as u8 {
            tracing::warn!(target: "bsc_protocol", got = format_args!("{:#04x}", msg_id), "Expected capability during handshake");
            return Poll::Ready(None);
        }

        match BscCapPacket::decode(&mut &slice[..]) {
            Ok(pkt) => {
                if pkt.protocol_version != BSC_PROTOCOL_VERSION {
                    tracing::warn!(target: "bsc_protocol", "Protocol version mismatch: {} != {}", pkt.protocol_version, BSC_PROTOCOL_VERSION);
                    return Poll::Ready(None);
                }

                tracing::debug!(target: "bsc_protocol", version = pkt.protocol_version, "Received peer capability");
                
                self.handshake_completed = true;
                self.handshake_deadline = None;

                if !self.is_dialer {
                    // Responder sends capability response
                    let response = Self::encode_command(BscCommand::SendCapability {
                        protocol_version: BSC_PROTOCOL_VERSION,
                        extra: Bytes::from_static(b"00")
                    });
                    tracing::debug!(target: "bsc_protocol", "BSC handshake completed (responder)");
                    Poll::Ready(Some(Some(response)))
                } else {
                    // Dialer just completes handshake
                    tracing::debug!(target: "bsc_protocol", "BSC handshake completed (dialer)");
                    Poll::Ready(Some(None))
                }
            }
            Err(e) => {
                tracing::warn!(target: "bsc_protocol", error = %e, "Failed to decode BSC capability during handshake");
                Poll::Ready(None)
            }
        }
    }

    /// Handle normal protocol messages after handshake
    fn handle_protocol_message(&self, frame: &BytesMut) {
        tracing::debug!(target: "bsc_protocol", "Handshake completed, processing normal message");
        let slice = frame.as_ref();
        let msg_id = slice[0];

        match msg_id {
            x if x == BscProtoMessageId::Votes as u8 => {
                tracing::debug!(target: "bsc_protocol", "Processing votes message");
                if let Ok(packet) = VotesPacket::decode(&mut &slice[..]) {
                    let count = packet.0.len();
                    handle_votes_broadcast(packet);
                    tracing::debug!(target: "bsc_protocol", count, "Processed votes packet");
                } else {
                    tracing::warn!(target: "bsc_protocol", "Failed to decode VotesPacket");
                }
            }
            x if x == BscProtoMessageId::Capability as u8 => {
                tracing::debug!(target: "bsc_protocol", "Processing additional capability message");
                if let Ok(packet) = BscCapPacket::decode(&mut &slice[..]) {
                    tracing::debug!(
                        target: "bsc_protocol",
                        version = packet.protocol_version,
                        extra_len = packet.extra.len(),
                        "Received additional peer capability"
                    );
                }
            }
            _ => {
                tracing::debug!(target: "bsc_protocol", msg_id = format_args!("{:#04x}", msg_id), "Unknown BSC message id");
            }
        }
    }
}

impl Stream for BscProtocolConnection {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        tracing::info!(
            target: "bsc_protocol", 
            handshake_completed = this.handshake_completed,
            is_dialer = this.is_dialer,
            "🔄 BSC poll_next called"
        );

        // Send initial capability if we're the dialer
        if let Some(initial_cmd) = this.initial_capability.take() {
            tracing::debug!(target: "bsc_protocol", "Sending initial capability as dialer");
            return Poll::Ready(Some(Self::encode_command(initial_cmd)));
        }

        loop {
            // Check for outgoing commands first
            if let Some(encoded_command) = this.poll_outgoing_commands(cx) {
                return Poll::Ready(Some(encoded_command));
            }

            // Get next incoming frame
            let raw_frame = match this.poll_incoming_frame(cx) {
                Poll::Ready(Some(Some(frame))) => frame,
                Poll::Ready(Some(None)) => continue, // Empty frame, try again
                Poll::Ready(None) => return Poll::Ready(None), // Connection closed
                Poll::Pending => return Poll::Pending,
            };

            // Process the frame based on handshake state
            if !this.handshake_completed {
                match this.handle_handshake_frame(&raw_frame, cx) {
                    Poll::Ready(Some(Some(response))) => return Poll::Ready(Some(response)),
                    Poll::Ready(Some(None)) => continue, // Handshake complete, no response needed
                    Poll::Ready(None) => return Poll::Ready(None), // Handshake failed
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                this.handle_protocol_message(&raw_frame);
                return Poll::Pending; // No response needed
            }
        }
    }
}


