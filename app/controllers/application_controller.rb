class ApplicationController < ActionController::Base
  include Authentication

  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  # CSRF protection
  protect_from_forgery with: :exception

  helper_method :remove_query_param

  private

  # Remove a query parameter from a URL using proper URI parsing
  # More robust than regex - handles URL encoding, edge cases, etc.
  #
  # @param url [String] The URL to modify
  # @param param_name [String] The query parameter name to remove
  # @return [String] The URL with the parameter removed
  #
  # @example
  #   remove_query_param("https://example.com?foo=bar&baz=qux", "foo")
  #   # => "https://example.com?baz=qux"
  def remove_query_param(url, param_name)
    uri = URI.parse(url)
    return url unless uri.query

    params = Rack::Utils.parse_query(uri.query)
    params.delete(param_name)

    uri.query = params.any? ? Rack::Utils.build_query(params) : nil
    uri.to_s
  rescue URI::InvalidURIError
    url
  end
end
