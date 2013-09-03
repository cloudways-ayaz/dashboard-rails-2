
require 'mcollective'
include MCollective::RPC
require 'md5'

class ServiceController < ApplicationController
    USER = "cloudways-dev-api"
    PASSWORD = "cloudways123+"
    skip_before_filter :verify_authenticity_token
    before_filter :init
    before_filter :authenticate
    verify :method => :post, :only => :add_customer

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
            rpc_client.progress = false
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
            rpc_client.progress = false
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
            rpc_client.progress = false
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
            rpc_client.progress = false
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

        facts = ['fqdn', 'hostname', 'cloudways_roles', 'cloudways_varnish_enabled']
        service_facts = {
            'cloudways_mysql_installed'         => 'mysql',
            'cloudways_nginx_installed'         => 'nginx',
            'cloudways_varnish_installed'       => 'varnish',
            'cloudways_memcached_installed'     => 'memcached',
            'cloudways_apache2_installed'       => 'apache2',
        }

        begin
            rpc_client = rpcclient('rpcutil', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.fact_filter "cloudways_customer", @customer_number
            rpc_client.timeout = @timeout
            rpc_client.progress = false
            rpc_response = rpc_client.get_facts(:facts => service_facts.keys.zip(facts).join(', '))
            print "facts = #{service_facts.keys.zip(facts).join(', ')}"
            host_list = []
            rpc_response.each do |resp|
                unless resp[:data][:values].nil?

                    roles = []
                    # 0 = varnish is enabled
                    # 1 = varnish is disabled
                    # 2 = varnish doesn't exist
                    is_varnish_enabled = 1

                    service_facts.each do |fact_name, service_name|
                        if resp[:data][:values].include?(fact_name)
                            val = resp[:data][:values][fact_name]
                            if val and val == '0'
                                roles.push(service_name)
                            end
                        end
                    end 

                    cw_roles = resp[:data][:values]['cloudways_roles']
                    begin

                        # only for 'standardweb' role do we check whether varnish is enabled or disabled.
                        # and if varnish is disabled, we do not provide it in the list of services even
                        # if varnish is installed.
                        if cw_roles.include?('standardweb')
                            varnish_enabled = resp[:data][:values]['cloudways_varnish_enabled']

                            if varnish_enabled
                                if varnish_enabled == "0"
                                    is_varnish_enabled = 0
                                    unless roles.include?('varnish')
                                        roles.push('varnish')
                                    end
                                elsif varnish_enabled == "1"
                                    is_varnish_enabled = 1
                                    roles.delete('varnish')
                                end
                            else
                                # if varnish_enabled is nil, we set the value to 2.
                                is_varnish_enabled = 2
                                roles.delete('varnish')
                            end
                        end
                    rescue NoMethodError => e
                    end

                    host_list.push({:fqdn => resp[:data][:values]['fqdn'], 
                                    :hostname => resp[:data][:values]['hostname'], 
                                    :roles => roles,
                                    :varnish_enabled => is_varnish_enabled,
                                    :cw_roles => cw_roles,
                    })
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
                @response[:msg] = "Customer added"
            end
        else
            @response[:status] = -1
            @response[:msg] = "Customer already present."
        end

        render :json => @response
    end


    #
    # Return selected facts values.
    # Input: hostname, customer_number_hash
    # 
    def get_dashboard_items
        facts_dict = {
            "ram"               =>  "memorysize",
            "ram_total"         =>  "memorytotal",
            "cloud_provider"    =>  "cloudways_cloud",
            "location"          =>  "cloudways_region",
            "roles"             =>  "cloudways_roles",
            "websites"          =>  "cloudways_websites_list",
            "public_ip"         =>  "cloudways_public_ip",
            "os"                =>  "operatingsystem",
            "os_release"        =>  "operatingsystemrelease",
            "os_family"         =>  "osfamily",
            "kernel"            =>  "kernel",
            "kernel_release"    =>  "kernelrelease",
            "distribution"      =>  "lsbdistdescription",
            "procs_count"       =>  "processorcount",
            "procs_type"        =>  "processor0",
            "arch"              =>  "architecture",
            "hardware_model"    =>  "hardwaremodel",
            "uptime"            =>  "uptime",
        }
        @customer_number = params[:customer_number]
        @hostname = params[:hostname]

        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Customer number parameter missing."
            @is_clean = false
        end

        if @hostname.nil?
            @response[:status] = -1
            @response[:msg] = "Hostname parameter missing."
            @is_clean = false
        end

        @customer_number = @params_verifier.get_customer_number(@customer_number)
        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Incorrect customer number provided."
            @is_clean = false
        end

        unless @is_clean
            return render :json => @response
        end


        begin
            rpc_client = rpcclient('rpcutil', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.fact_filter "cloudways_customer", @customer_number
            rpc_client.identity_filter @hostname
            rpc_client.timeout = @timeout

            facts_string = facts_dict.values.join(', ')
            rpc_response = rpc_client.get_facts(:facts => facts_dict.values.join(', '))

            facts_result = {}

            rpc_response = rpc_response[0]

            facts_dict.each do |fact_hash, fact_name|
                begin
                    fact_value = rpc_response.results[:data][:values][fact_name]
                rescue NoMethodError => e
                    fact_value = ''
                end
                facts_result[fact_hash] = fact_value
            end

            response = {
                :items => facts_result,
            }

            @response[:status] = 0
            @response[:response] = response
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end
end
