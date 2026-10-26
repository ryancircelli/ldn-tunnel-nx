// RyuLDN wire structs, mirroring ryu_ldn_nx sysmodule/source/protocol/types.hpp
// field for field (same names), checked against it by test/codec.test.ts.
import { array, bytes, struct } from "./struct.ts";

export const MAGIC = 0x4e444c52; // "RLDN"
export const VERSION = 1;
export const MAX_PACKET_SIZE = 131072;
export const HEADER_SIZE = 12;

export enum PacketId {
  Initialize = 0,
  Passphrase = 1,
  CreateAccessPoint = 2,
  CreateAccessPointPrivate = 3,
  ExternalProxy = 4,
  ExternalProxyToken = 5,
  ExternalProxyState = 6,
  SyncNetwork = 7,
  Reject = 8,
  RejectReply = 9,
  Scan = 10,
  ScanReply = 11,
  ScanReplyEnd = 12,
  Connect = 13,
  ConnectPrivate = 14,
  Connected = 15,
  Disconnect = 16,
  ProxyConfig = 17,
  ProxyConnect = 18,
  ProxyConnectReply = 19,
  ProxyData = 20,
  ProxyDisconnect = 21,
  SetAcceptPolicy = 22,
  SetAdvertiseData = 23,
  DebugLog = 0xc0, // console -> relay only; see Relay.debugLog
  UpdateCheck = 0xc1, // console -> relay: UpdateCheckRequest
  UpdateManifest = 0xc2, // relay -> console: SignedManifest, or empty when the channel has no release
  UpdateChunk = 0xc3, // console -> relay: UpdateChunkRequest
  UpdateChunkData = 0xc4, // relay -> console: UpdateChunkHeader + data
  Resume = 0xc5, // console -> relay on a new link: old session id (16) + room session id (16); see Relay.resume
  Ping = 254,
  NetworkError = 255,
}

// LdnServer's NetworkError enum (Network/Types/NetworkErrorMessage.cs).
export enum NetworkError {
  None = 0,
  PortUnreachable = 1,
  TooManyPlayers = 2,
  VersionTooLow = 3,
  VersionTooHigh = 4,
  ConnectFailure = 5,
  ConnectNotFound = 6,
  ConnectTimeout = 7,
  ConnectRejected = 8,
  RejectFailed = 9,
  BannedByServer = 127,
  Unknown = -1,
}

// ScanFilterFlag (LdnServer/Types/ScanFilterFlag.cs)
export const ScanFilterFlag = {
  LocalCommunicationId: 1 << 0,
  SessionId: 1 << 1,
  NetworkType: 1 << 2,
  MacAddress: 1 << 3,
  Ssid: 1 << 4,
  SceneId: 1 << 5,
} as const;

export const LdnHeader = struct("LdnHeader", [
  ["magic", "u32"],
  ["type", "u8"],
  ["version", "u8"],
  ["reserved", "u16"],
  ["data_size", "i32"],
]);

export const IntentId = struct("IntentId", [
  ["local_communication_id", "i64"],
  ["reserved1", "u16"],
  ["scene_id", "u16"],
  ["reserved2", "u32"],
]);

export const NetworkId = struct("NetworkId", [
  ["intent_id", IntentId],
  ["session_id", bytes(16)],
]);

export const Ssid = struct("Ssid", [
  ["length", "u8"],
  ["name", bytes(33)],
]);

export const NodeInfo = struct("NodeInfo", [
  ["ipv4_address", "u32"],
  ["mac_address", bytes(6)],
  ["node_id", "u8"],
  ["is_connected", "u8"],
  ["user_name", bytes(33)],
  ["reserved1", "u8"],
  ["local_communication_version", "u16"],
  ["reserved2", bytes(16)],
]);

export const CommonNetworkInfo = struct("CommonNetworkInfo", [
  ["mac_address", bytes(6)],
  ["ssid", Ssid],
  ["channel", "u16"],
  ["link_level", "u8"],
  ["network_type", "u8"],
  ["reserved", "u32"],
]);

export const LdnNetworkInfo = struct("LdnNetworkInfo", [
  ["security_parameter", bytes(16)],
  ["security_mode", "u16"],
  ["station_accept_policy", "u8"],
  ["unknown1", "u8"],
  ["reserved1", "u16"],
  ["node_count_max", "u8"],
  ["node_count", "u8"],
  ["nodes", array(NodeInfo, 8)],
  ["reserved2", "u16"],
  ["advertise_data_size", "u16"],
  ["advertise_data", bytes(384)],
  ["unknown2", bytes(140)],
  ["authentication_id", "u64"],
]);

export const NetworkInfo = struct("NetworkInfo", [
  ["network_id", NetworkId],
  ["common", CommonNetworkInfo],
  ["ldn", LdnNetworkInfo],
]);
export type NetworkInfo = ReturnType<typeof NetworkInfo.decode>;
export type NodeInfo = ReturnType<typeof NodeInfo.decode>;

export const InitializeMessage = struct("InitializeMessage", [
  ["id", bytes(16)],
  ["mac_address", bytes(6)],
]);

export const PassphraseMessage = struct("PassphraseMessage", [["passphrase", bytes(128)]]);

export const PingMessage = struct("PingMessage", [
  ["requester", "u8"],
  ["id", "u8"],
]);

export const DisconnectMessage = struct("DisconnectMessage", [["disconnect_ip", "u32"]]);

export const NetworkErrorMessage = struct("NetworkErrorMessage", [["error_code", "i32"]]);

export const ProxyInfo = struct("ProxyInfo", [
  ["source_ipv4", "u32"],
  ["source_port", "u16"],
  ["dest_ipv4", "u32"],
  ["dest_port", "u16"],
  ["protocol", "i32"],
]);

export const ProxyDataHeader = struct("ProxyDataHeader", [
  ["info", ProxyInfo],
  ["data_length", "u32"],
]);

export const ProxyConfig = struct("ProxyConfig", [
  ["proxy_ip", "u32"],
  ["proxy_subnet_mask", "u32"],
]);

export const ProxyConnectRequest = struct("ProxyConnectRequest", [["info", ProxyInfo]]);
export const ProxyConnectResponse = struct("ProxyConnectResponse", [["info", ProxyInfo]]);

export const ProxyDisconnectMessage = struct("ProxyDisconnectMessage", [
  ["info", ProxyInfo],
  ["disconnect_reason", "i32"],
]);

export const SecurityConfig = struct("SecurityConfig", [
  ["security_mode", "u16"],
  ["passphrase_size", "u16"],
  ["passphrase", bytes(64)],
]);

export const SecurityParameter = struct("SecurityParameter", [
  ["data", bytes(16)],
  ["session_id", bytes(16)],
]);

export const AddressEntry = struct("AddressEntry", [
  ["ipv4_address", "u32"],
  ["mac_address", bytes(6)],
  ["reserved", "u16"],
]);

export const AddressList = struct("AddressList", [["addresses", array(AddressEntry, 8)]]);
export type AddressEntry = ReturnType<typeof AddressEntry.decode>;

export const UserConfig = struct("UserConfig", [
  ["user_name", bytes(33)],
  ["unknown1", bytes(15)],
]);

export const NetworkConfig = struct("NetworkConfig", [
  ["intent_id", IntentId],
  ["channel", "u16"],
  ["node_count_max", "u8"],
  ["reserved1", "u8"],
  ["local_communication_version", "u16"],
  ["reserved2", bytes(10)],
]);

export const RyuNetworkConfig = struct("RyuNetworkConfig", [
  ["game_version", bytes(16)],
  ["private_ip", bytes(16)],
  ["address_family", "u32"],
  ["external_proxy_port", "u16"],
  ["internal_proxy_port", "u16"],
]);

export const CreateAccessPointRequest = struct("CreateAccessPointRequest", [
  ["security_config", SecurityConfig],
  ["user_config", UserConfig],
  ["network_config", NetworkConfig],
  ["ryu_network_config", RyuNetworkConfig],
]);

export const CreateAccessPointPrivateRequest = struct("CreateAccessPointPrivateRequest", [
  ["security_config", SecurityConfig],
  ["security_parameter", SecurityParameter],
  ["user_config", UserConfig],
  ["network_config", NetworkConfig],
  ["address_list", AddressList],
  ["ryu_network_config", RyuNetworkConfig],
]);

export const ConnectPrivateRequest = struct("ConnectPrivateRequest", [
  ["security_config", SecurityConfig],
  ["security_parameter", SecurityParameter],
  ["user_config", UserConfig],
  ["local_communication_version", "u32"],
  ["option_unknown", "u32"],
  ["network_config", NetworkConfig],
]);

export const ScanFilterFull = struct("ScanFilterFull", [
  ["network_id", NetworkId],
  ["network_type", "u32"],
  ["mac_address", bytes(6)],
  ["ssid", Ssid],
  ["reserved", bytes(16)],
  ["flag", "u32"],
]);

export const ConnectRequest = struct("ConnectRequest", [
  ["security_config", SecurityConfig],
  ["user_config", UserConfig],
  ["local_communication_version", "u32"],
  ["option_unknown", "u32"],
  ["_padding", "u32"],
  ["network_info", NetworkInfo],
]);

export const SetAcceptPolicyRequest = struct("SetAcceptPolicyRequest", [["accept_policy", "u8"]]);

export const RejectRequest = struct("RejectRequest", [
  ["node_id", "u32"],
  ["disconnect_reason", "u32"],
]);

// Auto-update (relay-only extension).
export const UPDATE_MANIFEST_MAGIC = 0x4d554c52; // "RLUM" little-endian
export const UPDATE_MANIFEST_FORMAT = 1;
export const UPDATE_CHUNK_SIZE = 4096;
export const UPDATE_MAX_BLOB_SIZE = 4 * 1024 * 1024;
export enum UpdateChannel { Off = 0, Stable = 1, Test = 2 }

export const UpdateCheckRequest = struct("UpdateCheckRequest", [
  ["running_build", "u32"],
  ["rejected_build", "u32"],
  ["channel", "u8"],
  ["label_len", "u8"],
  ["reserved", bytes(2)],
  ["label", bytes(32)],
  ["version", bytes(32)],
]);

export const UpdateManifest = struct("UpdateManifest", [
  ["magic", "u32"],
  ["format", "u32"],
  ["build", "u32"],
  ["exefs_size", "u32"],
  ["exefs_sha256", bytes(32)],
  ["overlay_size", "u32"],
  ["overlay_sha256", bytes(32)],
  ["version", bytes(32)],
  ["reserved", bytes(12)],
]);

export const SignedManifest = struct("SignedManifest", [
  ["manifest", UpdateManifest],
  ["signature", bytes(64)],
]);

export const UpdateChunkRequest = struct("UpdateChunkRequest", [
  ["sha256", bytes(32)],
  ["offset", "u32"],
  ["length", "u32"],
]);

export const UpdateChunkHeader = struct("UpdateChunkHeader", [
  ["sha256", bytes(32)],
  ["offset", "u32"],
  ["total_size", "u32"],
]);

export const ALL_STRUCTS = [
  LdnHeader, IntentId, NetworkId, Ssid, NodeInfo, CommonNetworkInfo, LdnNetworkInfo, NetworkInfo,
  InitializeMessage, PassphraseMessage, PingMessage, DisconnectMessage, NetworkErrorMessage,
  ProxyInfo, ProxyDataHeader, ProxyConfig, ProxyConnectRequest, ProxyConnectResponse, ProxyDisconnectMessage,
  SecurityConfig, SecurityParameter, AddressEntry, AddressList, UserConfig, NetworkConfig, RyuNetworkConfig,
  CreateAccessPointRequest, CreateAccessPointPrivateRequest, ConnectPrivateRequest, ScanFilterFull,
  ConnectRequest, SetAcceptPolicyRequest, RejectRequest,
  UpdateCheckRequest, UpdateManifest, SignedManifest, UpdateChunkRequest, UpdateChunkHeader,
];

/** Builds one wire packet: 12-byte header + payload. */
export function packet(type: PacketId, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  LdnHeader.encode({ magic: MAGIC, type, version: VERSION, reserved: 0, data_size: payload.length }, out);
  out.set(payload, HEADER_SIZE);
  return out;
}

/**
 * Validates one WebSocket message as exactly one packet (README.md, "Wire contract").
 * Returns null when the relay must close with 1002.
 */
export function parsePacket(msg: Uint8Array): { type: number; payload: Uint8Array } | null {
  if (msg.length < HEADER_SIZE) return null;
  const h = LdnHeader.decode(msg);
  if (h.magic !== MAGIC || h.version !== VERSION) return null;
  // LdnServer: header + data >= MaxPacketSize throws and drops the session.
  if (h.data_size < 0 || HEADER_SIZE + h.data_size >= MAX_PACKET_SIZE) return null;
  if (h.data_size !== msg.length - HEADER_SIZE) return null;
  return { type: h.type, payload: msg.subarray(HEADER_SIZE) };
}
