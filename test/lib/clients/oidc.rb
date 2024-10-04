require "test_helper"

class OIDCTest < ActiveSupport::TestCase
  attr_reader :client_id
  attr_reader :client_secret
  setup do
    @client = Clients::Vault
  end

  def configure_oidc_provider
    # create test user for oidc
    oidc_provider.logical.delete("/sys/auth/userpass")
    oidc_provider.logical.write("/sys/auth/userpass", type: "userpass")
    oidc_provider.logical.write("/auth/userpass/users/#{TEST_USER[:name]}", password: TEST_USER[:password])

    # create oidc provider app
    oidc_provider.logical.write(WEBAPP_NAME,
                               redirect_uris: "http://localhost:8250/oidc/callback",
                               assignments: "allow_all")

    app = oidc_provider.logical.read(WEBAPP_NAME)
    @client_id = app.data[:client_id]
    @client_secret = app.data[:client_secret]

    # create email scope
    oidc_provider.logical.write("identity/oidc/scope/email",
                               template: '{"email": {{identity.entity.metadata.email}}}')

    oidc_provider.logical.write(PROVIDER[:name],
                               issuer: PROVIDER[:host],
                               allowed_client_ids: @client_id,
                               scopes_supported: "email")
    oidc_provider.logical.write("identity/entity",
                               policies: "default",
                               name: TEST_USER[:name],
                               metadata: "email=#{TEST_USER[:email]}",
                               disabled: false)
    provider = oidc_provider.logical.read(PROVIDER[:name])

    op_entity = oidc_provider.logical.read("identity/entity/name/#{TEST_USER[:name]}")
    op_entity_id = op_entity.data[:id]
    op_auth_list = oidc_provider.logical.read("/sys/auth")
    up_accessor = op_auth_list.data[:"userpass/"][:accessor]
    oidc_provider.logical.write("identity/entity-alias",
                               name: TEST_USER[:name],
                               canonical_id: op_entity_id,
                               mount_accessor: up_accessor)
  end

  test ".configure_oidc_user" do
    configure_oidc_provider
    @client.configure_oidc_client(@client_id, @client_secret, "#{PROVIDER[:host]}/v1/#{PROVIDER[:name]}")
    policy = <<-EOH
           path "sys" {
           policy = "deny"
           }
           EOH
    @client.configure_oidc_user(TEST_USER[:name], TEST_USER[:email], policy)
    assert true
    puts "gbjdone"
  end

  private
  WEBAPP_NAME = "identity/oidc/client/my-webapp"
  PROVIDER = {name: "identity/oidc/provider/my-provider",
              host: "http://oidc_provider:8300",
              token: "root_token"}
  TEST_USER = {name: "test", password: "test", email: "test@example.com"}

  def oidc_provider
    ::Vault::Client.new(
          address: PROVIDER[:host],
          token: PROVIDER[:token]
    )
  end

  def vault_client
    ::Vault::Client.new(
          address: vault_addr,
          token: vault_token
    )
  end

  def vault_addr
    Config[:vault_addr]
  end

  def vault_token
    Config[:vault_token]
  end
end
