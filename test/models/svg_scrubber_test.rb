require "test_helper"

class SvgScrubberTest < ActiveSupport::TestCase
  def scrub(svg)
    Loofah.xml_document(svg).scrub!(SvgScrubber.new).to_xml
  end

  test "strips embedded script elements" do
    svg = %(<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><path d="M0 0"/></svg>)

    cleaned = scrub(svg)

    refute_match(/<script/i, cleaned)
    refute_match(/alert/i, cleaned)
    assert_match(/<path/, cleaned)
  end

  test "strips on* event handler attributes while preserving the element" do
    svg = %(<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle cx="5" cy="5" r="3" onclick="steal()"/></svg>)

    cleaned = scrub(svg)

    refute_match(/onload/i, cleaned)
    refute_match(/onclick/i, cleaned)
    refute_match(/alert|steal/, cleaned)
    assert_match(/<svg/, cleaned)
    assert_match(/<circle/, cleaned)
  end

  test "strips attribute values that point at javascript: or data: URIs" do
    svg = %(<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><path d="M0 0" fill="data:text/html,evil"/></a></svg>)

    cleaned = scrub(svg)

    refute_match(/javascript:/i, cleaned)
    refute_match(/data:text\/html/i, cleaned)
  end

  test "preserves a benign icon unchanged in shape" do
    svg = %(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2 L22 22 L2 22 Z" fill="#000"/></svg>)

    cleaned = scrub(svg)

    assert_match(/<svg/, cleaned)
    assert_match(/<path/, cleaned)
    assert_match(/M12 2 L22 22 L2 22 Z/, cleaned)
    assert_match(/viewBox="0 0 24 24"/, cleaned)
  end
end
