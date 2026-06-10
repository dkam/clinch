require "test_helper"

class ApplicationTest < ActiveSupport::TestCase
  test "sanitizes an SVG icon uploaded via UploadedFile (regression for FileNotFoundError)" do
    app = applications(:kavita_app)

    svg = %(<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><path d="M0 0"/></svg>)
    tempfile = Tempfile.new(["icon", ".svg"]).tap do |t|
      t.write(svg)
      t.rewind
    end
    uploaded = ActionDispatch::Http::UploadedFile.new(
      tempfile: tempfile,
      filename: "icon.svg",
      type: "image/svg+xml"
    )

    # Previously raised ActiveStorage::FileNotFoundError because the
    # before_validation callback called icon.download before the blob was
    # uploaded to disk.
    assert_nothing_raised do
      app.update!(icon: uploaded)
    end

    cleaned = app.icon.download
    refute_match(/<script/i, cleaned)
    assert_match(/<path/, cleaned)
  ensure
    tempfile&.close
    tempfile&.unlink
  end

  test "icon_dark is independently attachable and SVG-sanitized" do
    app = applications(:kavita_app)

    svg = %(<svg xmlns="http://www.w3.org/2000/svg"><script>boom()</script><circle cx="5" cy="5" r="3"/></svg>)
    tempfile = Tempfile.new(["dark", ".svg"]).tap do |t|
      t.write(svg)
      t.rewind
    end
    uploaded = ActionDispatch::Http::UploadedFile.new(
      tempfile: tempfile,
      filename: "dark.svg",
      type: "image/svg+xml"
    )

    assert_nothing_raised do
      app.update!(icon_dark: uploaded)
    end

    assert app.icon_dark.attached?
    cleaned = app.icon_dark.download
    refute_match(/<script/i, cleaned)
    assert_match(/<circle/, cleaned)
  ensure
    tempfile&.close
    tempfile&.unlink
  end

  test "rejects backchannel_logout_uri pointing at internal addresses (SSRF guard)" do
    app = applications(:kavita_app)

    internal_uris = [
      "http://127.0.0.1/logout",
      "http://localhost/logout",
      "https://169.254.169.254/latest/meta-data/",
      "http://10.0.0.5/logout",
      "http://192.168.1.10/logout"
    ]

    internal_uris.each do |uri|
      app.backchannel_logout_uri = uri
      refute app.valid?, "expected #{uri} to be rejected"
      assert_includes app.errors[:backchannel_logout_uri].join, "private, loopback, or link-local"
    end
  end

  test "allows backchannel_logout_uri pointing at a public host" do
    app = applications(:kavita_app)
    app.backchannel_logout_uri = "https://relying-party.example.com/backchannel-logout"

    assert app.valid?, app.errors.full_messages.to_sentence
  end
end
