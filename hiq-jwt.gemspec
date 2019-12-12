lib = File.expand_path('../lib/', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'hiq-jwt/version'

Gem::Specification.new do |spec|
  spec.name = 'hiq-jwt'
  spec.version = HiqJWT.gem_version
  spec.authors = [
    'Jack Dunham'
  ]
  spec.email = 'jack.dunham@healthiq.com'
  spec.summary = 'JSON Web Token implementation in Ruby'
  spec.description = 'A pure ruby implementation of the RFC 7519 OAuth JSON Web Token (JWT) standard.'
  spec.homepage = 'https://github.com/healthiqeng/ruby-jwt.git'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.1'

  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(spec|gemfiles|coverage|bin)/}) || f.end_with?('.gem')}
  spec.executables = []
  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = %w[lib]

  spec.add_development_dependency 'appraisal'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'simplecov-json'
  spec.add_development_dependency 'codeclimate-test-reporter'
  spec.add_development_dependency 'codacy-coverage'
  spec.add_development_dependency 'rbnacl'
  # RSASSA-PSS support provided by OpenSSL +2.1
  spec.add_development_dependency 'openssl', '~> 2.1'
end
