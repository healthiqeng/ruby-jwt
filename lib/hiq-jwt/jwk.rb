# frozen_string_literal: true

require_relative 'jwk/rsa'
require_relative 'jwk/key_finder'

module HiqJWT
  module JWK
    MAPPINGS = {
      'RSA' => ::HiqJWT::JWK::RSA,
      OpenSSL::PKey::RSA => ::HiqJWT::JWK::RSA
    }.freeze

    class << self
      def import(jwk_data)
        raise HiqJWT::JWKError, 'Key type (kty) not provided' unless jwk_data[:kty]

        MAPPINGS.fetch(jwk_data[:kty].to_s) do |kty|
          raise HiqJWT::JWKError, "Key type #{kty} not supported"
        end.import(jwk_data)
      end

      def create_from(keypair)
        MAPPINGS.fetch(keypair.class) do |klass|
          raise HiqJWT::JWKError, "Cannot create JWK from a #{klass.name}"
        end.new(keypair)
      end

      alias new create_from
    end
  end
end
