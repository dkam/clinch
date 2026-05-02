# Loofah scrubber that strips dangerous content from SVG files
# while preserving safe SVG elements and attributes for icon display.
class SvgScrubber < Loofah::Scrubber
  ALLOWED_ELEMENTS = %w[
    svg g defs use symbol
    circle ellipse line path polygon polyline rect
    text tspan textPath
    clipPath mask pattern
    linearGradient radialGradient stop
    filter feBlend feColorMatrix feComponentTransfer feComposite
    feConvolveMatrix feDiffuseLighting feDisplacementMap feFlood
    feGaussianBlur feImage feMerge feMergeNode feMorphology
    feOffset feSpecularLighting feTile feTurbulence
    title desc metadata
  ].freeze

  ALLOWED_ATTRIBUTES = %w[
    id class style
    x y x1 y1 x2 y2 cx cy r rx ry
    width height viewBox preserveAspectRatio
    d points
    fill stroke stroke-width stroke-linecap stroke-linejoin stroke-dasharray
    opacity fill-opacity stroke-opacity
    transform translate rotate scale
    font-family font-size font-weight text-anchor
    clip-path mask filter
    gradientUnits gradientTransform spreadMethod
    offset stop-color stop-opacity
    dx dy textLength lengthAdjust
    xmlns xmlns:xlink
    color display visibility overflow
    fill-rule clip-rule
    marker-start marker-mid marker-end
  ].freeze

  # Loofah hands attribute names back in their source case (e.g. "viewBox").
  # Compare against a downcased copy so SVG-spec camelCase attributes aren't
  # stripped from legitimate icons.
  ALLOWED_ATTRIBUTES_LOOKUP = ALLOWED_ATTRIBUTES.map(&:downcase).to_set.freeze

  # Event handler attributes that must always be removed
  EVENT_HANDLER_PATTERN = /\Aon/i

  def initialize
    @direction = :top_down
  end

  def scrub(node)
    return CONTINUE if node.text? || node.cdata?

    if node.element?
      if ALLOWED_ELEMENTS.include?(node.name)
        # Remove disallowed and event handler attributes
        node.attribute_nodes.each do |attr|
          attr.remove unless safe_attribute?(attr)
        end
        return CONTINUE
      end
    end

    node.remove
    STOP
  end

  private

  def safe_attribute?(attr)
    name = attr.name.downcase
    return false if name.match?(EVENT_HANDLER_PATTERN)
    return false if attr.value&.match?(/javascript:|data:/i)
    ALLOWED_ATTRIBUTES_LOOKUP.include?(name)
  end
end
