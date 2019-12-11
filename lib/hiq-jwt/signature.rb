# frozen_string_literal: true

require 'hiq-jwt/security_utils'
require 'openssl'
require 'hiq-jwt/algos/hmac'
require 'hiq-jwt/algos/eddsa'
require 'hiq-jwt/algos/ecdsa'
require 'hiq-jwt/algos/rsa'
require 'hiq-jwt/algos/ps'
require 'hiq-jwt/algos/unsupported'
begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module HiqJWT
  # Signature logic for JWT
  module Signature
    extend self
    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Ps,
      Algos::Unsupported
    ].freeze
    ToSign = Struct.new(:algorithm, :msg, :key)
    ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)

    def sign(algorithm, msg, key)
      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      algo.sign ToSign.new(algorithm, msg, key)
    end

    def verify(algorithm, key, signing_input, signature)
      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      verified = algo.verify(ToVerify.new(algorithm, key, signing_input, signature))
      raise(HiqJWT::VerificationError, 'Signature verification raised') unless verified
    rescue OpenSSL::PKey::PKeyError
      raise HiqJWT::VerificationError, 'Signature verification raised'
    ensure
      OpenSSL.errors.clear
    end
  end
end
