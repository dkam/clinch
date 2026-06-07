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
end
