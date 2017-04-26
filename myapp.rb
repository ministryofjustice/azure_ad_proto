#-------------------------------------------------------------------------------
# Copyright (c) 2015 Micorosft Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-------------------------------------------------------------------------------

require 'adal'
require 'json'
require 'net/http'
require 'securerandom'
require 'sinatra'
require 'uri'
require 'pry'

AUTHORITY = 'login.windows.net'
RESOURCE = 'https://graph.windows.net' # Azure AD Graph API NOTE: this is not the MS Graph API
# RESOURCE = 'https://graph.microsoft.com' # MS Graph API NOTE: this is not the Azure AD Graph API
CLIENT_ID = ENV['AAD_PROTO_CLIENT_ID']
CLIENT_SECRET = ENV['AAD_PROTO_CLIENT_SECRET']
TENANT_ID = ENV['AAD_PROTO_TENANT_ID']

# AuthenticationContext is specific to a tenant. Our application only cares
# about one tenant, so we only need one AuthenticationContext.
auth_ctx = ADAL::AuthenticationContext.new(AUTHORITY, TENANT_ID)

# ADAL::ClientCredential is one of several ways that you can identify your
# client application. It contains a client id and a client secret, which are
# assigned to you by Azure when you register your application.
client_cred = ADAL::ClientCredential.new(CLIENT_ID, CLIENT_SECRET)

# ADAL supports four logging options: VERBOSE, INFO, WARN and ERROR.
# They are defined as constants in ADAL::Logger and are used in ADAL::Logging,
# the mix-in factory module that provides Loggers to the various ADAL classes.
# By default, log_level = ADAL::Logger::ERROR so only error messages will be
# displayed.
ADAL::Logging.log_level = ADAL::Logger::VERBOSE

# ADAL allows you to redirect log outputs to a file or any Ruby object
# that implements IO. By default they are sent to STDOUT.
ADAL::Logging.log_output = 'my_adal_logs.log'

# This is Sinatra specific code that allows storing data as a browser cookie.
configure do
  enable :sessions
  set :session_secret, 'secret'
end

# Public landing page for the web app.
get '/' do
  'This is a public page. Anyone can see it.<br/>' \
  'If you have credentials, you can view the protected phone book ' \
  "for your organization <a href='/secure'>here</a>." \
  "You can query using this field: #{query_form}"
end

def query_form
  <<~HTML
  <form method="POST", action="/query">
    <p>email: <input name='email' type="text"></p>
    <input type="submit">
  </form>
  HTML
end

post '/query' do
  email = params[:email]

  if email
    # binding.pry
    resource_uri = aad_resource("&$filter=accountEnabled eq true and (userPrincipalName eq '#{email}' or mail eq '#{email}')")
    headers = { 'authorization' => session[:access_token] }
    http = Net::HTTP.new(resource_uri.hostname, resource_uri.port)
    http.use_ssl = true
    response = http.get(resource_uri, headers).body
    parse(response)
  end
end

# In order to access /secure, the user needs an access token for the resource
# (https://graph.windows.net) that /secure will be displaying.
before '/secure' do
  redirect to('/auth') unless session[:access_token]
end

# Now that we have an access token, we use it to access the resource.
# The details here are specific to your resource.
get '/secure' do
  resource_uri = aad_resource
  headers = { 'authorization' => session[:access_token] }
  http = Net::HTTP.new(resource_uri.hostname, resource_uri.port)
  http.use_ssl = true
  response = http.get(resource_uri, headers).body
  parse(response)
end

def aad_resource query = nil
  URI(RESOURCE +
      '/' +
      TENANT_ID +
      '/users?api-version=1.5' +
      (query || '')
      )
end

def parse response
  # binding.pry
  graph = JSON.parse(response)
  # puts '<<<<<<<<<<<<<<<<<response>>>>>>>>>>>>>'
  # pp graph
  # puts '<<<<<<<<<<<<<<<<<response>>>>>>>>>>>>>'

  'Here is your phone book.<br/><br/>' +
    graph['value'].map do |user|
      %(Display Name: #{user['displayName']}<br/>
        Given Name: #{user['givenName']}<br/>
        Surname: #{user['surname']}<br/>
        Address: #{user['streetAddress']}, #{user['city']}, #{user['country']}<br/>
        email Address: #{user['mail']}<br/>
        Telephone: #{user['telephoneNumber']}<br/>
        mobile: #{user['mobile']}<br/>
        Job Title: #{user['jobTitle']}<br/>
        Department: #{user['department']}<br/>
        <br/><br/>)
    end.join(' ') +
    "You can log out <a href='/logout'>here</a>.<br/>" \
    "Or refresh the token <a href='/refresh'>here.</a>"
end


# Removes the access token from the session. The user will have to authenticate
# again if they wish to revisit their phone book.
get '/logout' do
  session.clear
  redirect to('/')
end

get '/auth' do
  # Request authorization by redirecting the user. ADAL will help create the
  # URL, but it will not make the actual request for you. In this case, the
  # request is made by Sinatra's redirect function.
  redirect auth_ctx.authorization_request_url(RESOURCE, CLIENT_ID, uri), 303
end

# The authorization code is returned from the authorization server as
# params[:code]. We pass this to ADAL to acquire an access_token.
post '/auth' do
  token_response = auth_ctx.acquire_token_with_authorization_code(
    params[:code], uri, client_cred, RESOURCE)
  case token_response
  when ADAL::SuccessResponse
    # ADAL successfully exchanged the authorization code for an access_token.
    # The token_response includes other information but we only care about the
    # access token and the refresh token.
    session[:access_token] = token_response.access_token
    session[:refresh_token] = token_response.refresh_token
    redirect to('/secure')
  when ADAL::ErrorResponse
    # ADAL failed to exchange the authorization code for an access_token.
    redirect to('/')
  end
end

before '/refresh' do
  redirect to('/auth') unless session[:refresh_token]
end

get '/refresh' do
  token_response = auth_ctx.acquire_token_with_refresh_token(
    session[:refresh_token], client_cred, RESOURCE)
  session[:access_token] = token_response.access_token
  session[:refresh_token] = token_response.refresh_token
  redirect to('/secure')
end
