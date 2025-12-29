class AddTokenPrefixToTokens < ActiveRecord::Migration[8.1]
  def up
    add_column :oidc_access_tokens, :token_prefix, :string, limit: 8
    add_column :oidc_refresh_tokens, :token_prefix, :string, limit: 8

    # Backfill existing tokens with prefix and digest
    say_with_time "Backfilling token prefixes and digests..." do
      [OidcAccessToken, OidcRefreshToken].each do |klass|
        klass.reset_column_information  # Ensure Rails knows about new column

        klass.where(token_prefix: nil).find_each do |token|
          next unless token.token.present?

          updates = {}

          # Compute HMAC prefix
          prefix = klass.compute_token_prefix(token.token)
          updates[:token_prefix] = prefix if prefix.present?

          # Backfill digest if missing
          if token.token_digest.nil?
            updates[:token_digest] = BCrypt::Password.create(token.token)
          end

          token.update_columns(updates) if updates.any?
        end

        say "  #{klass.name}: #{klass.where.not(token_prefix: nil).count} tokens backfilled"
      end
    end

    add_index :oidc_access_tokens, :token_prefix
    add_index :oidc_refresh_tokens, :token_prefix
  end

  def down
    remove_index :oidc_access_tokens, :token_prefix
    remove_index :oidc_refresh_tokens, :token_prefix
    remove_column :oidc_access_tokens, :token_prefix
    remove_column :oidc_refresh_tokens, :token_prefix
  end
end
