-- Schema v2: whether a presented credential was vouched for. verified,
-- rejected (unverified and the response was 401/403), unverified, or null
-- without a credential. Only a verified credential stands in for the peer.

ALTER TABLE turns ADD COLUMN credential_status TEXT;
CREATE INDEX turns_peer_rejected ON turns (peer_key, ts_us) WHERE credential_status = 'rejected';
