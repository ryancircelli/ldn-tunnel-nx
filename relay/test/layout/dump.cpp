// Prints sizeof/offsetof for every struct the relay encodes, straight from the
// sysmodule's types.hpp. Regenerate with tools/dump-layout.sh.
#include <cstddef>
#include <cstdio>
#include "protocol/types.hpp"
using namespace ryu_ldn::protocol;

static bool first = true;
#define S(T) printf("%s\n  \"" #T "\": {\"$size\": %zu", first ? "" : ",", sizeof(T)); first = false;
#define F(T, f) printf(", \"" #f "\": %zu", offsetof(T, f));
#define E printf("}");

int main() {
  printf("{");
  S(LdnHeader) F(LdnHeader, magic) F(LdnHeader, type) F(LdnHeader, version) F(LdnHeader, reserved) F(LdnHeader, data_size) E
  S(IntentId) F(IntentId, local_communication_id) F(IntentId, reserved1) F(IntentId, scene_id) F(IntentId, reserved2) E
  S(NetworkId) F(NetworkId, intent_id) F(NetworkId, session_id) E
  S(Ssid) F(Ssid, length) F(Ssid, name) E
  S(NodeInfo) F(NodeInfo, ipv4_address) F(NodeInfo, mac_address) F(NodeInfo, node_id) F(NodeInfo, is_connected) F(NodeInfo, user_name) F(NodeInfo, reserved1) F(NodeInfo, local_communication_version) F(NodeInfo, reserved2) E
  S(CommonNetworkInfo) F(CommonNetworkInfo, mac_address) F(CommonNetworkInfo, ssid) F(CommonNetworkInfo, channel) F(CommonNetworkInfo, link_level) F(CommonNetworkInfo, network_type) F(CommonNetworkInfo, reserved) E
  S(LdnNetworkInfo) F(LdnNetworkInfo, security_parameter) F(LdnNetworkInfo, security_mode) F(LdnNetworkInfo, station_accept_policy) F(LdnNetworkInfo, unknown1) F(LdnNetworkInfo, reserved1) F(LdnNetworkInfo, node_count_max) F(LdnNetworkInfo, node_count) F(LdnNetworkInfo, nodes) F(LdnNetworkInfo, reserved2) F(LdnNetworkInfo, advertise_data_size) F(LdnNetworkInfo, advertise_data) F(LdnNetworkInfo, unknown2) F(LdnNetworkInfo, authentication_id) E
  S(NetworkInfo) F(NetworkInfo, network_id) F(NetworkInfo, common) F(NetworkInfo, ldn) E
  S(InitializeMessage) F(InitializeMessage, id) F(InitializeMessage, mac_address) E
  S(PassphraseMessage) F(PassphraseMessage, passphrase) E
  S(PingMessage) F(PingMessage, requester) F(PingMessage, id) E
  S(DisconnectMessage) F(DisconnectMessage, disconnect_ip) E
  S(NetworkErrorMessage) F(NetworkErrorMessage, error_code) E
  S(ProxyInfo) F(ProxyInfo, source_ipv4) F(ProxyInfo, source_port) F(ProxyInfo, dest_ipv4) F(ProxyInfo, dest_port) F(ProxyInfo, protocol) E
  S(ProxyDataHeader) F(ProxyDataHeader, info) F(ProxyDataHeader, data_length) E
  S(ProxyConfig) F(ProxyConfig, proxy_ip) F(ProxyConfig, proxy_subnet_mask) E
  S(ProxyConnectRequest) F(ProxyConnectRequest, info) E
  S(ProxyConnectResponse) F(ProxyConnectResponse, info) E
  S(ProxyDisconnectMessage) F(ProxyDisconnectMessage, info) F(ProxyDisconnectMessage, disconnect_reason) E
  S(SecurityConfig) F(SecurityConfig, security_mode) F(SecurityConfig, passphrase_size) F(SecurityConfig, passphrase) E
  S(SecurityParameter) F(SecurityParameter, data) F(SecurityParameter, session_id) E
  S(AddressEntry) F(AddressEntry, ipv4_address) F(AddressEntry, mac_address) F(AddressEntry, reserved) E
  S(AddressList) F(AddressList, addresses) E
  S(UserConfig) F(UserConfig, user_name) F(UserConfig, unknown1) E
  S(NetworkConfig) F(NetworkConfig, intent_id) F(NetworkConfig, channel) F(NetworkConfig, node_count_max) F(NetworkConfig, reserved1) F(NetworkConfig, local_communication_version) F(NetworkConfig, reserved2) E
  S(RyuNetworkConfig) F(RyuNetworkConfig, game_version) F(RyuNetworkConfig, private_ip) F(RyuNetworkConfig, address_family) F(RyuNetworkConfig, external_proxy_port) F(RyuNetworkConfig, internal_proxy_port) E
  S(CreateAccessPointRequest) F(CreateAccessPointRequest, security_config) F(CreateAccessPointRequest, user_config) F(CreateAccessPointRequest, network_config) F(CreateAccessPointRequest, ryu_network_config) E
  S(CreateAccessPointPrivateRequest) F(CreateAccessPointPrivateRequest, security_config) F(CreateAccessPointPrivateRequest, security_parameter) F(CreateAccessPointPrivateRequest, user_config) F(CreateAccessPointPrivateRequest, network_config) F(CreateAccessPointPrivateRequest, address_list) F(CreateAccessPointPrivateRequest, ryu_network_config) E
  S(ConnectPrivateRequest) F(ConnectPrivateRequest, security_config) F(ConnectPrivateRequest, security_parameter) F(ConnectPrivateRequest, user_config) F(ConnectPrivateRequest, local_communication_version) F(ConnectPrivateRequest, option_unknown) F(ConnectPrivateRequest, network_config) E
  S(ScanFilterFull) F(ScanFilterFull, network_id) F(ScanFilterFull, network_type) F(ScanFilterFull, mac_address) F(ScanFilterFull, ssid) F(ScanFilterFull, reserved) F(ScanFilterFull, flag) E
  S(ConnectRequest) F(ConnectRequest, security_config) F(ConnectRequest, user_config) F(ConnectRequest, local_communication_version) F(ConnectRequest, option_unknown) F(ConnectRequest, _padding) F(ConnectRequest, network_info) E
  S(SetAcceptPolicyRequest) F(SetAcceptPolicyRequest, accept_policy) E
  S(RejectRequest) F(RejectRequest, node_id) F(RejectRequest, disconnect_reason) E
  S(UpdateCheckRequest) F(UpdateCheckRequest, running_build) F(UpdateCheckRequest, rejected_build) F(UpdateCheckRequest, channel) F(UpdateCheckRequest, label_len) F(UpdateCheckRequest, reserved) F(UpdateCheckRequest, label) F(UpdateCheckRequest, version) E
  S(UpdateManifest) F(UpdateManifest, magic) F(UpdateManifest, format) F(UpdateManifest, build) F(UpdateManifest, exefs_size) F(UpdateManifest, exefs_sha256) F(UpdateManifest, overlay_size) F(UpdateManifest, overlay_sha256) F(UpdateManifest, version) F(UpdateManifest, reserved) E
  S(SignedManifest) F(SignedManifest, manifest) F(SignedManifest, signature) E
  S(UpdateChunkRequest) F(UpdateChunkRequest, sha256) F(UpdateChunkRequest, offset) F(UpdateChunkRequest, length) E
  S(UpdateChunkHeader) F(UpdateChunkHeader, sha256) F(UpdateChunkHeader, offset) F(UpdateChunkHeader, total_size) E
  printf("\n}\n");
}
