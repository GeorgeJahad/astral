require "test_helper"

class SecretsTest < ActionDispatch::IntegrationTest
  test "#create unauthorized" do
    post secrets_path
    assert_response :unauthorized
  end

  test "#create with faulty token (encoded with different signing key)" do
    post secrets_path, headers: { "Authorization" => "Bearer #{jwt_unauthorized}" }
    assert_response :unauthorized
  end

  test "#create or update a secret" do
    create_secret
    assert_response :success
    %w[ data metadata lease_id ].each do |key|
      assert_includes response.parsed_body["secret"].keys, key
    end
  end

  private

  def create_secret
    # make a path
    path = "top/secret/gbj7"
    # create the secret
    post secrets_path, headers: { "Authorization" => "Bearer #{jwt_authorized}" },
         params: { secret: { path: path, groups: "group1", data: { password: "sicr3t" } } }
    path
  end

  def remove_pki_engine
    vault_client.sys.unmount "pki_astral"
  end
end
