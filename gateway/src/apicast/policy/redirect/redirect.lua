--- Redirect policy
-- This policy captures arguments in a URL and rewrites/redirects the request
-- to the given URL using those arguments.
-- For example, we can specify a matching rule with arguments like
-- '/{orderId}/{accountId}' and a template that specifies how to rewrite the
-- URL using those arguments, for example:
-- 'http://test.server.com/sales/v2/{orderId}?account={accountId}'.
-- In that case, the request '/123/456' will be transformed into
-- 'http://test.server.com/sales/v2/123?account=456'

local RedirectRule = require('redirect_rule')
local QueryParams = require('apicast.query_params')
local Upstream = require('apicast.upstream')
local balancer = require('apicast.balancer')

local ipairs = ipairs
local insert = table.insert

local policy = require('apicast.policy')
local _M = policy.new('Redirect policy')

local new = _M.new

function _M.new(config)
  local self = new(config)

  self.rules = {}

  for _, config_rule in ipairs(config.rules or {}) do
    local rule = RedirectRule.new(
      config_rule.http_method,
      config_rule.match_rule,
      config_rule.template
    )
    
    ngx.log(ngx.DEBUG, 'Rule created: ', rule)

    insert(self.rules, rule) 
  end

  return self
end

local function change_uri(new_uri)
  ngx.req.set_uri(new_uri)
end

-- When a param in 'new_params' exist in the request, this function replaces
-- its value. When it does not exist, it simply adds it.
-- This function does not delete or modify the params in the query that do not
-- appear in 'new_params'.
local function set_query_params(params, param_vals)
  local query_params = QueryParams.new()

  for i = 1, #params do
    query_params:set(params[i], param_vals[i])
  end
end

-- This function only applies the first rule that matches.
-- Defining rules that take into account previous matches can become quite
-- complex and I don't think it's a common use case. Notice that it's possible
-- to do that anyway by chaining multiple instances of this policy.
function _M:rewrite(context)
  local uri = ngx.var.uri
  local http_method = ngx.var.request_method
  
  for _, rule in ipairs(self.rules) do
    local match, new_uri, params, param_vals, upstream_url = rule:match(uri, http_method)

    if match then
      ngx.log(ngx.DEBUG, 'Rule matched: ', rule)

      if upstream_url then
        context[self] = Upstream.new(upstream_url)
      end

      change_uri(new_uri)
      set_query_params(params, param_vals)
      return
    end
  end
end

function _M:content(context)
  local upstream = context[self]

  if upstream then
    upstream:call(context)
  else
    return nil, 'no upstream'
  end
end

_M.balancer = balancer.call

return _M
