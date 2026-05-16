// Package replay will issue baseline and variant HTTP requests and collect
// responses. It is intentionally empty in Packet 1.
//
// TODO(packet-2): implement the replay engine — rate limiting, concurrency,
// timeout enforcement, optional redirect following, and per-identity
// credential application (including Tier-1 refresh hooks).
package replay
