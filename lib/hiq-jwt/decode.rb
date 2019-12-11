# frozen_string_literal: true

require 'json'

require 'hiq-jwt/signature'
require 'hiq-jwt/verify'
# JWT::Decode module
module HiqJWT
  # Decoding logic for JWT
  class Decode
    def initialize(jwt, key, verify, options, &keyfinder)
      raise(HiqJWT::DecodeError, 'Nil JSON web token') unless jwt
      @jwt = jwt
      @key = key
      @options = options
      @segments = jwt.split('.')
      @verify = verify
      @signature = ''
      @keyfinder = keyfinder
    end

    def decode_segments
      validate_segment_count!
      if @verify
        decode_crypto
        verify_signature
        verify_claims
      end
      raise(HiqJWT::DecodeError, 'Not enough or too many segments') unless header && payload
      [payload, header]
    end

    private

    def verify_signature
      @key = find_key(&@keyfinder) if @keyfinder
      @key = ::HiqJWT::JWK::KeyFinder.new(jwks: @options[:jwks]).key_for(header['kid']) if @options[:jwks]

      raise(HiqJWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
      raise(HiqJWT::IncorrectAlgorithm, 'Expected a different algorithm') unless options_includes_algo_in_header?

      Signature.verify(header['alg'], @key, signing_input, @signature)
    end

    def options_includes_algo_in_header?
      allowed_algorithms.include? header['alg']
    end

    def allowed_algorithms
      if @options.key?(:algorithm)
        [@options[:algorithm]]
      else
        @options[:algorithms] || []
      end
    end

    def find_key(&keyfinder)
      key = (keyfinder.arity == 2 ? yield(header, payload) : yield(header))
      raise HiqJWT::DecodeError, 'No verification key available' unless key
      key
    end

    def verify_claims
      Verify.verify_claims(payload, @options)
    end

    def validate_segment_count!
      return if segment_length == 3
      return if !@verify && segment_length == 2 # If no verifying required, the signature is not needed

      raise(HiqJWT::DecodeError, 'Not enough or too many segments')
    end

    def segment_length
      @segments.count
    end

    def decode_crypto
      @signature = HiqJWT::Base64.url_decode(@segments[2])
    end

    def header
      @header ||= parse_and_decode @segments[0]
    end

    def payload
      @payload ||= parse_and_decode @segments[1]
    end

    def signing_input
      @segments.first(2).join('.')
    end

    def parse_and_decode(segment)
      HiqJWT::JSON.parse(HiqJWT::Base64.url_decode(segment))
    rescue ::JSON::ParserError
      raise HiqJWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
