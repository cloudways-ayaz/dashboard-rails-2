
require 'mcollective'
include MCollective::RPC
require 'md5'

class ServiceController < ApplicationController
    USER = "cloudways-dev-api"
    PASSWORD = "cloudways123+"
    skip_before_filter :verify_authenticity_token
    before_filter :init
    before_filter :authenticate

    def authenticate
        authenticate_or_request_with_http_basic('Administration') do |username, password|
            @params_verifier.verify_auth(username, password)
        end
    end

    def init 
        @params_verifier = ServiceHelper::ParamsVerifier.new()
        @service_name = nil
        @customer_number = nil
        @response = {:status => 0}
        @is_clean = true
        @timeout = 25
        @rpc_options = {:configfile => "/home/ayaz/.mcollective/client.cfg"}
    end

    def check_params
        @is_clean = false
        @service_name = params[:service_name]
        @customer_number = params[:customer_number]
        @hostname = params[:hostname]

        if @service_name.nil?
            @response[:status] = -1
            @response[:msg] = "Service name parameter missing."
            return @response
        end

        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Customer number parameter missing."
            return @response
        end

        if @hostname.nil?
            @response[:status] = -1
            @response[:msg] = "Hostname parameter missing."
            return @response
        end


        @service_name = @params_verifier.get_service(@service_name)
        if @service_name.nil?
            @response[:status] = -1
            @response[:msg] = "Incorrect service name provided."
            return @response
        end

        @customer_number = @params_verifier.get_customer_number(@customer_number)
        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Incorrect customer number provided."
            return @response
        end

        @is_clean = true
        @response
    end


    def status
        @response = check_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('service', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end

            rpc_response = rpc_client.status(:service => @service_name)
            response = {
                :statuscode => rpc_response[0][:statuscode],
                :statusmsg => rpc_response[0][:statusmsg],
                :status => rpc_response[0][:data][:status],
                :sender => rpc_response[0][:sender]
            }

            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "Server error: #{e}"
        end

        render :json => @response
    end


    def start
        @response = check_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('service', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.start(:service => @service_name)
            response = {
                :statuscode => rpc_response[0][:statuscode],
                :statusmsg => rpc_response[0][:statusmsg],
                :status => rpc_response[0][:data][:status],
                :sender => rpc_response[0][:sender]
            }

            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    def stop
        @response = check_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('service', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.stop(:service => @service_name)
            response = {
                :statuscode => rpc_response[0][:statuscode],
                :statusmsg => rpc_response[0][:statusmsg],
                :status => rpc_response[0][:data][:status],
                :sender => rpc_response[0][:sender]
            }

            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    def restart
        @response = check_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('service', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.restart(:service => @service_name)
            response = {
                :statuscode => rpc_response[0][:statuscode],
                :statusmsg => rpc_response[0][:statusmsg],
                :status => rpc_response[0][:data][:status],
                :sender => rpc_response[0][:sender]
            }

            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


    def get_host_list
        @customer_number = params[:customer_number]

        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Customer number parameter missing."
            return render :json => @response
        end

        @customer_number = @params_verifier.get_customer_number(@customer_number)
        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Incorrect customer number provided."
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('rpcutil', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.fact_filter "cloudways_customer", @customer_number
            rpc_client.timeout = @timeout
            rpc_response = rpc_client.get_facts(:facts => 'fqdn, hostname, cloudways_roles, cloudways_varnish_enabled')
            host_list = []
            rpc_response.each do |resp|
                unless resp[:data][:values].nil?
                    roles = resp[:data][:values]['cloudways_roles']
                    begin

                        # For standardweb role, replace it with apache2, nginx, and
                        # varnish.
                        # However, before doing that, we need to ensure whether
                        # varnish is enabled or disabled on the remote server..
                        if roles.include?('standardweb')
                            varnish_enabled = resp[:data][:values]['cloudways_varnish_enabled']
                            if varnish_enabled == "0":
                                standard_web_roles = "apache2,varnish,nginx"
                            else
                                standard_web_roles = "apache2,nginx"
                            end
                            roles = roles.gsub(/\bstandardweb\b/, standard_web_roles)
                        end


                        # The apache role returned actually
                        # corresponds to apache2 service.
                        roles = roles.gsub(/\bapache\b/, "apache2")
                        roles = roles.split(',')
                    rescue NoMethodError => e
                        roles = []
                    end

                    host_list.push({:fqdn => resp[:data][:values]['fqdn'], 
                                    :hostname => resp[:data][:values]['hostname'], 
                                    :roles => roles})
                end
            end
            response = {:hostnames => host_list}
            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    #
    # Add a new customer_number and its hash to the JSON file that stores
    # customer numbers.
    # Input: customer_number
    #
    def add_customer
        customer_number = params[:customer_number]

        if customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Customer number parameter missing."
            return render :json => @response
        end
        customer_number_hash = MD5.new(customer_number).hexdigest

        status = @params_verifier.add_customer(customer_number, customer_number_hash)

        if status
            begin
                @params_verifier.write_params_to_file()
            rescue Exception => e
                @response[:status] = -2
                @response[:msg] = "Failed to update customer. #{e}"
            else
                @response[:status] = 0
                @response[:response] = "Customer added"
            end
        else
            @response[:status] = -1
            @response[:msg] = "Customer already present."
        end

        render :json => @response
    end
end
