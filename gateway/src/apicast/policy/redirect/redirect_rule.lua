local re_gsub = ngx.re.gsub
local re_match = ngx.re.match
local re_gmatch = ngx.re.gmatch
local re_split = require('ngx.re').split
local insert = table.insert
local format = string.format
local ipairs = ipairs
local setmetatable = setmetatable
local Upstream = require('apicast.upstream')

local _M = {}
local mt = { __index = _M }

function mt:__tostring()
  local say = "RedirectRule {http_method: '".. self.method ..
              "', rule: '" .. self.rule_string .. 
              "' ,regex: " .. self.regex_rule .. 
              "', upstream: '" .. self.upstream_url .. 
              "', path_template: '" .. self.path_template .. "'}"
  return say
end

local function split(string, separator, max_matches)
  return re_split(string, separator, 'oj', nil, max_matches)
end

-- Returns a list of named args extracted from a match_rule.
-- For example, for the rule /{abc}/{def}?{ghi}=1, it returns this list:
-- { "{abc}", "{def}", "{ghi}" }.
--
-- Notice that each named arg is wrapped between "{" and "}". That's because
-- we always need to match those "{}", so we can add them here and avoid
-- string concatenations later.
local function extract_named_args(match_rule)
  local iterator, err = re_gmatch(match_rule, [[\{(.+?)\}]], 'oj')

  if not iterator then
    return nil, err
  end

  local named_args = {}

  while true do
    local m, err_iter = iterator()
    if err_iter then
      return nil, err_iter
    end

    if not m then
      break
    end

    insert(named_args, format('{%s}', m[1]))
  end

  return named_args
end

-- Extracts the new upstream server from the given template.
-- For example, if the given template is "https://test.server.com:443/abc/def/{ghi}",
-- the result would be https://test.server.com:443.
local function extract_upstream_url_from_template(template)
  local captures, err = re_match(template, "^http(s)?://(.*?)/", "oj")
  local upstream_url = captures[0]

  -- Remove trailing slash if we have a match
  if upstream_url then
    upstream_url = upstream_url:sub(1, -2)
  end

  -- Check if we have a valid upstream url
  local upstream, up_err = Upstream.new(upstream_url)

  if upstream then
    return upstream_url
  else
    ngx.log(ngx.WARN, 'failed to initialize upstream from url: ', upstream_url, ' err: ', up_err)
  end
end

-- Converts given method_string to uppercase and checks if the rule 
-- uses a valid HTTP method.
local function check_method(method_string)
  local http_methods = {"GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "MKCOL", "COPY", "MOVE", "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK", "PATCH", "TRACE"}
  
  local m = method_string:upper()

  -- Check if uppercase method m is in allowed methods table
  for _, value in pairs(http_methods) do
    if m == value then
      return m
    end
  end
  
  ngx.log(ngx.WARN, "failed to inititlaize rule with HTTP method '", m, "'")
end

-- Remove the upstream url from template to get just the path template.
local function remove_upstream_from_template(template, upstream_url)
  local path_template = template
  if upstream_url then
    path_template = path_template:sub(#upstream_url + 1)
  end

  return path_template
end

-- Rules contain {} for named args. This function replaces those with "()" to
-- be able to capture those args when matching the regex.
local function transform_rule_to_regex(match_rule)
  return re_gsub(
    match_rule,
    [[\{.+?\}]],
    [[([\w-.~%!$$&'()*+,;=@:]+)]], -- Same as in the MappingRule module
    'oj'
  )
end

-- Transforms a string representing the args of a query like:
-- "a=1&b=2&c=3" into 2 tables one with the arguments, and
-- another with the values:
-- { 'a', 'b', 'c' } and { '1', '2', '3' }.
local function string_params_to_tables(string_params)
  if not string_params then return {}, {} end

  local args = {}
  local values = {}

  local params_split = split(string_params, '&', 2)

  for _, param in ipairs(params_split) do
    local parts = split(param, '=', 2) -- avoid unpack, not jitted.
    insert(args, parts[1])
    insert(values, parts[2])
  end

  return args, values
end

local function replace_in_template(args, vals, template)
  local res = template

  for i = 1, #args do
    res = re_gsub(res, args[i], vals[i], 'oj')
  end

  return res
end

local function uri_and_params_from_template(template)
  local parts = split(template, [[\?]], 2) -- avoid unpack, not jitted.
  return parts[1], parts[2]
end

function _M.new(method, match_rule, template)
  local self = setmetatable({}, mt)

  self.rule_string = match_rule
  self.method = check_method(method)
  self.named_args = extract_named_args(match_rule)
  self.regex_rule = transform_rule_to_regex(match_rule)
  self.upstream_url = extract_upstream_url_from_template(template)
  self.path_template = remove_upstream_from_template(template, self.upstream_url)

  return self
end

function _M:match(path, http_method)
  if http_method ~= self.method then
    return false
  end

  local matches = re_match(path, self.regex_rule, 'oj')

  if not matches or #self.named_args ~= #matches then
    return false
  end

  local replaced_template = replace_in_template(
    self.named_args, matches, self.path_template)

  local uri, raw_params = uri_and_params_from_template(replaced_template)

  local params, vals = string_params_to_tables(raw_params)

  return true, uri, params, vals, self.upstream_url
end

return _M
