-- Schema v2, two more facts from the package: the client source port (to
-- tell users apart behind one NAT address) and the request time in whole
-- milliseconds as the package stamps it. Both nullable; null on a v1 event.

ALTER TABLE turns ADD COLUMN remote_port INTEGER;
ALTER TABLE turns ADD COLUMN ts_ms INTEGER;
