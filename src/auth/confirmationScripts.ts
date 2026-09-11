// One Redis key per confirmation. TIME and state transitions run together on the server.
const NOW = `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
`;

export const ISSUE_CONFIRMATION =
  NOW +
  `
local expires = now + tonumber(ARGV[3])
local record = cjson.encode({
  binding_hash = ARGV[1], arguments_hash = ARGV[2],
  state = 'pending', expires_at = expires
})
local inserted = redis.call('SET', KEYS[1], record, 'NX', 'PX', ARGV[3])
if not inserted then return {'collision'} end
return {'issued', tostring(expires)}
`;

export const CLAIM_CONFIRMATION =
  NOW +
  `
local raw = redis.call('GET', KEYS[1])
if not raw then return {'invalid'} end
local record = cjson.decode(raw)
if record.binding_hash ~= ARGV[1] or record.arguments_hash ~= ARGV[2] then
  return {'invalid'}
end
if record.state == 'done' then return {'done', record.result} end
if record.expires_at <= now then return {'invalid'} end
if record.state == 'in_progress' and record.lease_until > now then
  return {'in_progress', tostring(record.lease_until - now)}
end
if record.state ~= 'pending' and record.state ~= 'in_progress' then return {'invalid'} end
record.state = 'in_progress'
record.owner = ARGV[3]
record.lease_until = now + tonumber(ARGV[4])
redis.call('SET', KEYS[1], cjson.encode(record), 'PX',
  math.max(record.expires_at - now, tonumber(ARGV[5])))
return {'claimed'}
`;

export const COMPLETE_CONFIRMATION = `
local raw = redis.call('GET', KEYS[1])
if not raw then return {'lost'} end
local record = cjson.decode(raw)
if record.binding_hash ~= ARGV[1] or record.arguments_hash ~= ARGV[2]
  or record.state ~= 'in_progress' or record.owner ~= ARGV[3] then
  return {'lost'}
end
record.state = 'done'
record.result = ARGV[4]
record.owner = nil
record.lease_until = nil
redis.call('SET', KEYS[1], cjson.encode(record), 'PX', ARGV[5])
return {'completed'}
`;
