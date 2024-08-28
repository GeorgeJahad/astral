class ObtainCert
  include Interactor

  def call
    if cert = Services::CertificateService.new.issue_cert(context.request)
      context.cert = cert
    else
      context.fail!(message: "Failed to issue certificate")
    end
  rescue => e
    context.fail!(message: e.message)
  end
end
