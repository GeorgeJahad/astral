#require "test_helper"

class VaultTest < ActiveSupport::TestCase
  attr_reader :intermediate_ca_mount
  attr_reader :root_ca_mount
  attr_reader :kv_mount
  attr_reader :policies
  attr_reader :entity_name
  attr_reader :alias_name
  attr_reader :client_id
  attr_reader :client_secret

  setup do
    @client = Clients::Vault
    @token = Clients::Vault.token
    Clients::Vault.token = vault_token
    @root_ca_mount = SecureRandom.hex(4)
    @intermediate_ca_mount = SecureRandom.hex(4)
    @kv_mount = SecureRandom.hex(4)
    @policies = SecureRandom.hex(4)
    @entity_name = SecureRandom.hex(4)
    @alias_name = SecureRandom.hex(4)
  end

  teardown do
    Clients::Vault.token = @token
    vault_client.sys.unmount(root_ca_mount)
    vault_client.sys.unmount(intermediate_ca_mount)
  end

  test ".configure_kv" do
    @client.stub :kv_mount, kv_mount do
      assert @client.configure_kv
      engines = vault_client.sys.mounts
      assert_equal "kv", engines[kv_mount.to_sym].type
    end
  end

  test ".configure_pki" do
    @client.stub :root_ca_mount, root_ca_mount do
      @client.stub :intermediate_ca_mount, intermediate_ca_mount do
        assert @client.configure_pki

        [ root_ca_mount, intermediate_ca_mount ].each do |mount|
          engines = vault_client.sys.mounts
          assert_equal "pki", engines[mount.to_sym].type

          read_cert = vault_client.logical.read("#{mount}/cert/ca").data[:certificate]
          assert_match "BEGIN CERTIFICATE", read_cert

          cluster_config = vault_client.logical.read("#{mount}/config/cluster").data
          assert_equal "#{vault_addr}/v1/#{mount}", cluster_config[:path]
          assert_equal "#{vault_addr}/v1/#{mount}", cluster_config[:aia_path]
        end

        role_config = vault_client.logical.read("#{intermediate_ca_mount}/roles/astral").data
        assert_not_nil role_config[:issuer_ref]
        assert_equal 720.hours, role_config[:max_ttl]
        assert_equal true, role_config[:allow_any_name]
      end
    end
  end

  test ".rotate_token" do
    # begins with default token
    assert_equal vault_token, @client.token
    assert @client.rotate_token
    # now has a new token
    assert_not_equal vault_token, @client.token
    # ensure we can write with the new token
    assert_instance_of Vault::Secret, @client.kv_write("testing/secret", { password: "sicr3t" })
  end

  test "#entity" do
    entity =  @client.read_entity(@entity_name)
    assert_nil entity

    @client.put_entity(@entity_name, @policies)
    entity =  @client.read_entity(@entity_name)
    assert_equal @policies, entity.data[:policies][0]

    @client.delete_entity(@entity_name)
    entity =  @client.read_entity(@entity_name)
    assert_nil entity
  end

  test "#entity_alias" do
    # confirm no entity yet
    err = assert_raises RuntimeError do
      @client.read_entity_alias(@entity_name, @alias_name)
    end
    assert_match /no such entity/, err.message

    # confirm no alias yet
    @client.put_entity(@entity_name, @policies)
    err = assert_raises RuntimeError do
      @client.read_entity_alias(@entity_name, @alias_name)
    end
    assert_match /no such alias/, err.message

    # create alias
    auth_method = "token"
    @client.put_entity_alias(@entity_name, @alias_name, auth_method)
    entity_alias =  @client.read_entity_alias(@entity_name, @alias_name)
    assert_equal auth_method, entity_alias.data[:mount_type]

    # confirm deleted alias
    assert_equal true, @client.delete_entity_alias(@entity_name, @alias_name)
    err = assert_raises RuntimeError do
      @client.delete_entity_alias(@entity_name, @alias_name)
    end
    assert_match /no such alias/, err.message
  end

  def configure_oidc_provider
    oidc_provider.logical.delete("/sys/auth/userpass")
    oidc_provider.logical.write("/sys/auth/userpass", type: "userpass")
    oidc_provider.logical.write("auth/userpass/users/end-user", password: "securepassword")

    # create oidc provider app
    oidc_provider.logical.write("identity/oidc/client/my-webapp",
                               redirect_uris: "http://localhost:8250/oidc/callback",
                               assignments: "allow_all")

    app = oidc_provider.logical.read("identity/oidc/client/my-webapp")
    @client_id = app.data[:client_id]
    @client_secret = app.data[:client_secret]
    oidc_provider.logical.write("identity/oidc/scope/email",
                               template: '{"email": {{identity.entity.metadata.email}}}')

    oidc_provider.logical.write("identity/oidc/provider/my-provider",
                               issuer: "http://oidc_provider:8300",
                               allowed_client_ids: @client_id,
                               scopes_supported: "email")
    oidc_provider.logical.write("identity/entity",
                               policies: "default",
                               name: "end-user",
                               metadata: "email=vault@hashicorp.com",
                               disabled: false)
    provider = oidc_provider.logical.read("identity/oidc/provider/my-provider")

    op_entity = oidc_provider.logical.read("identity/entity/name/end-user")
    op_entity_id = op_entity.data[:id]
    op_auth_list = oidc_provider.logical.read("/sys/auth")
    up_accessor = op_auth_list.data[:"userpass/"][:accessor]
    oidc_provider.logical.write("identity/entity-alias",
                               name: "end-user",
                               canonical_id: op_entity_id,
                               mount_accessor: up_accessor)
  end

  def configure_oidc_client
    #configure oidc client
    vault_client.logical.delete("/sys/auth/oidc")
    vault_client.logical.write("/sys/auth/oidc", type: "oidc")
    vault_client.logical.write("auth/oidc/config",
                               oidc_discovery_url: "http://oidc_provider:8300/v1/identity/oidc/provider/my-provider",
                               oidc_client_id: @client_id,
                               oidc_client_secret: @client_secret,
                               default_role: "reader")
    policy = <<-EOH
      path "sys" {
      policy = "deny"
    }
    EOH
    vault_client.sys.put_policy("reader", policy)
    vault_client.logical.write("auth/oidc/role/reader",
                               bound_audiences: @client_id,
                               allowed_redirect_uris: "http://localhost:8200/ui/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback,http://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback,http://127.0.0.1:8250/oidc/callback",
                               user_claim: "email",
                               oidc_scopes: "email",
                               token_policies: "reader")
  end

  def test_oidc
    configure_oidc_provider
    configure_oidc_client
    policy = <<-EOH
      path "sys" {
      policy = "deny"
    }
    EOH
    vault_client.sys.put_policy("manager", policy)

    vault_client.logical.write("identity/entity",
                               policies: "manager",
                               name: "end-user",
                               disabled: false)
    entity = vault_client.logical.read("identity/entity/name/end-user")
    entity_id = entity.data[:id]
    auth_list = vault_client.logical.read("/sys/auth")
    oidc_accessor = auth_list.data[:"oidc/"][:accessor]
    vault_client.logical.write("identity/entity-alias",
                               name: "vault@hashicorp.com",
                               canonical_id: entity_id,
                               mount_accessor: oidc_accessor)

  end

  private

  def oidc_provider
    ::Vault::Client.new(
          address: "http://oidc_provider:8300",
          token: "root_token"
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
