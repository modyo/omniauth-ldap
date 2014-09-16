#this code borrowed pieces from activeldap and net-ldap

require 'rack'
require 'net/ldap'
require 'net/ntlm'
require 'sasl'
require 'kconv'
module OmniAuth
  module LDAP
    class Adaptor
      class LdapError < StandardError;
      end
      class ConfigurationError < StandardError;
      end
      class AuthenticationError < StandardError;
      end
      class ConnectionError < StandardError;
      end

      VALID_ADAPTER_CONFIGURATION_KEYS = [:host, :port, :method, :bind_dn, :password, :try_sasl, :sasl_mechanisms, :uid, :base, :allow_anonymous, :filter,
                                          :ldap2_host, :ldap2_port, :ldap2_method, :ldap2_bind_dn, :ldap2_password, :ldap2_try_sasl, :ldap2_sasl_mechanisms, :ldap2_uid, :ldap2_base, :ldap2_allow_anonymous, :ldap2_filter,
                                          :ldap3_host, :ldap3_port, :ldap3_method, :ldap3_bind_dn, :ldap3_password, :ldap3_try_sasl, :ldap3_sasl_mechanisms, :ldap3_uid, :ldap3_base, :ldap3_allow_anonymous, :ldap3_filter]

      # A list of needed keys. Possible alternatives are specified using sub-lists.
      MUST_HAVE_KEYS = [:host, :port, :method, [:uid, :filter], :base]

      METHOD = {
          :ssl => :simple_tls,
          :tls => :start_tls,
          :plain => nil,
      }

      attr_accessor :bind_dn, :password
      attr_accessor :ldap2_bind_dn, :ldap2_password
      attr_accessor :ldap3_bind_dn, :ldap3_password
      attr_reader :connection, :uid, :base, :auth, :filter
      attr_reader :ldap2_connection, :ldap2_uid, :ldap2_base, :ldap2_auth, :ldap2_filter
      attr_reader :ldap3_connection, :ldap3_uid, :ldap3_base, :ldap3_auth, :ldap3_filter

      def self.validate(configuration={})
        message = []
        MUST_HAVE_KEYS.each do |names|
          names = [names].flatten
          missing_keys = names.select { |name| configuration[name].nil? }
          if missing_keys == names
            message << names.join(' or ')
          end
        end
        raise ArgumentError.new(message.join(",") +" MUST be provided") unless message.empty?
      end

      def initialize(configuration={})
        Adaptor.validate(configuration)
        @configuration = configuration.dup
        @configuration[:allow_anonymous] ||= false
        @logger = @configuration.delete(:logger)
        VALID_ADAPTER_CONFIGURATION_KEYS.each do |name|
          instance_variable_set("@#{name}", @configuration[name])
        end


        method = ensure_method(@method)
        config = {
            :host => @host,
            :port => @port,
            :encryption => method,
            :base => @base
        }
        @bind_method = @try_sasl ? :sasl : (@allow_anonymous||!@bind_dn||!@password ? :anonymous : :simple)


        @auth = sasl_auths({:username => @bind_dn, :password => @password}).first if @bind_method == :sasl
        @auth ||= {:method => @bind_method,
                   :username => @bind_dn,
                   :password => @password
        }
        config[:auth] = @auth
        @connection = Net::LDAP.new(config)

        # Connection N°2
        ldap2_method = ensure_method(@ldap2_method)
        ldap2_config = {
            :host => @ldap2_host,
            :port => @ldap2_port,
            :encryption => ldap2_method,
            :base => @ldap2_base
        }
        @ldap2_bind_method = @ldap2_try_sasl ? :sasl : (@ldap2_allow_anonymous||!@ldap2_bind_dn||!@ldap2_password ? :anonymous : :simple)


        @ldap2_auth = sasl_auths({:username => @ldap2_bind_dn, :password => @ldap2_password}).first if @ldap2_bind_method == :sasl
        @ldap2_auth ||= {:method => @ldap2_bind_method,
                         :username => @ldap2_bind_dn,
                         :password => @ldap2_password
        }
        ldap2_config[:auth] = @ldap2_auth
        @ldap2_connection = Net::LDAP.new(ldap2_config)

        # Connection N°3
        ldap3_method = ensure_method(@ldap3_method)
        ldap3_config = {
            :host => @ldap3_host,
            :port => @ldap3_port,
            :encryption => ldap3_method,
            :base => @ldap3_base
        }
        @ldap3_bind_method = @ldap3_try_sasl ? :sasl : (@ldap3_allow_anonymous||!@ldap3_bind_dn||!@ldap3_password ? :anonymous : :simple)


        @ldap3_auth = sasl_auths({:username => @ldap3_bind_dn, :password => @ldap3_password}).first if @ldap3_bind_method == :sasl
        @ldap3_auth ||= {:method => @ldap3_bind_method,
                   :username => @bind_dn,
                   :password => @password
        }
        ldap3_config[:auth] = @ldap3_auth
        @ldap3_connection = Net::LDAP.new(ldap3_config)


      end

      #:base => "dc=yourcompany, dc=com",
      # :filter => "(mail=#{user})",
      # :password => psw
      def bind_as(args = {})

        args1 = args.dup
        args2 = args.dup
        args3 = args.dup

        result = false
        @connection.open do |me|

          rs = me.search args1
          if rs and rs.first and dn = rs.first.dn
            password = args1[:password]
            method = args1[:method] || @method
            password = password.call if password.respond_to?(:call)
            if method == 'sasl'
              result = rs.first if me.bind(sasl_auths({:username => dn, :password => password}).first)
            else
              result = rs.first if me.bind(:method => :simple, :username => dn,
                                           :password => password)
            end

            return result if result

          elsif @ldap2_host.present?
            @ldap2_connection.open do |me|

              rs = me.search args2
              if rs and rs.first and dn = rs.first.dn
                password = args2[:password]
                method = args2[:method] || @ldap2_method
                password = password.call if password.respond_to?(:call)
                if method == 'sasl'
                  result = rs.first if me.bind(sasl_auths({:username => dn, :password => password}).first)
                else
                  result = rs.first if me.bind(:method => :simple, :username => dn,
                                               :password => password)
                end

                return result if result

              elsif @ldap3_host.present?
                @ldap3_connection.open do |me|

                  rs = me.search args3
                  if rs and rs.first and dn = rs.first.dn
                    password = args3[:password]
                    method = args3[:method] || @ldap3_method
                    password = password.call if password.respond_to?(:call)
                    if method == 'sasl'
                      result = rs.first if me.bind(sasl_auths({:username => dn, :password => password}).first)
                    else
                      result = rs.first if me.bind(:method => :simple, :username => dn,
                                                   :password => password)
                    end
                  end

                  return result if result
                end
              end
            end
          end
        end

      end

      private
      def ensure_method(method)
        method ||= "plain"
        normalized_method = method.to_s.downcase.to_sym
        return METHOD[normalized_method] if METHOD.has_key?(normalized_method)

        available_methods = METHOD.keys.collect { |m| m.inspect }.join(", ")
        format = "%s is not one of the available connect methods: %s"
        raise ConfigurationError, format % [method.inspect, available_methods]
      end

      def sasl_auths(options={})
        auths = []
        sasl_mechanisms = options[:sasl_mechanisms] || @sasl_mechanisms
        sasl_mechanisms.each do |mechanism|
          normalized_mechanism = mechanism.downcase.gsub(/-/, '_')
          sasl_bind_setup = "sasl_bind_setup_#{normalized_mechanism}"
          next unless respond_to?(sasl_bind_setup, true)
          initial_credential, challenge_response = send(sasl_bind_setup, options)
          auths << {
              :method => :sasl,
              :initial_credential => initial_credential,
              :mechanism => mechanism,
              :challenge_response => challenge_response
          }
        end
        auths
      end

      def sasl_bind_setup_digest_md5(options)
        bind_dn = options[:username]
        initial_credential = ""
        challenge_response = Proc.new do |cred|
          pref = SASL::Preferences.new :digest_uri => "ldap/#{@host}", :username => bind_dn, :has_password? => true, :password => options[:password]
          sasl = SASL.new("DIGEST-MD5", pref)
          response = sasl.receive("challenge", cred)
          response[1]
        end
        [initial_credential, challenge_response]
      end

      def sasl_bind_setup_gss_spnego(options)
        bind_dn = options[:username]
        psw = options[:password]
        raise LdapError.new("invalid binding information") unless (bind_dn && psw)

        nego = proc { |challenge|
          t2_msg = Net::NTLM::Message.parse(challenge)
          bind_dn, domain = bind_dn.split('\\').reverse
          t2_msg.target_name = Net::NTLM::encode_utf16le(domain) if domain
          t3_msg = t2_msg.response({:user => bind_dn, :password => psw}, {:ntlmv2 => true})
          t3_msg.serialize
        }
        [Net::NTLM::Message::Type1.new.serialize, nego]
      end

    end
  end
end
