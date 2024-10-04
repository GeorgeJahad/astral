module Clients
  class Vault
    class << self
      def configure_oidc_client(id, secret, issuer)
        client.logical.delete("/sys/auth/oidc")
        client.logical.write("/sys/auth/oidc", type: "oidc")
        client.logical.write("auth/oidc/config",
                                   oidc_discovery_url: issuer,
                                   oidc_client_id: id,
                                   oidc_client_secret: secret,
                                   default_role: "reader")
        policy = <<-EOH
              path "sys" {
              policy = "deny"
              }
              EOH
        client.sys.put_policy("reader", policy)
        client.logical.write("auth/oidc/role/reader",
                                   bound_audiences: id,
                                   allowed_redirect_uris: "http://localhost:8200/ui/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback,http://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback,http://127.0.0.1:8250/oidc/callback",
                                   user_claim: "email",
                                   oidc_scopes: "email",
                                   token_policies: "reader")

      end
      def configure_oidc_user(name, email, policy)
        client.sys.put_policy(email, policy)
        client.logical.write("identity/entity",
                                   policies: email,
                                   name: name,
                                   disabled: false)
        entity = client.logical.read("identity/entity/name/#{name}")
        entity_id = entity.data[:id]
        auth_list = client.logical.read("/sys/auth")
        oidc_accessor = auth_list.data[:"oidc/"][:accessor]
        client.logical.write("identity/entity-alias",
                                   name: email,
                                   canonical_id: entity_id,
                                   mount_accessor: oidc_accessor)

      end
    end
  end
end
