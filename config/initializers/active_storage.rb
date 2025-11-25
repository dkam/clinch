# Configure ActiveStorage content type resolution
Rails.application.config.after_initialize do
  # Ensure SVG files are served with the correct content type
  ActiveStorage::Blob.class_eval do
    def content_type_for_serving
      # Override content type for SVG files
      if filename.extension == "svg" && content_type == "application/octet-stream"
        "image/svg+xml"
      else
        content_type
      end
    end
  end
end
