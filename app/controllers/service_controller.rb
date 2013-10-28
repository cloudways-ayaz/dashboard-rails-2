
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

    def check_customer_number_and_hostname_params
        @is_clean = false
        @customer_number = params[:customer_number]
        @hostname = params[:hostname]

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

        @customer_number = @params_verifier.get_customer_number(@customer_number)
        if @customer_number.nil?
            @response[:status] = -1
            @response[:msg] = "Incorrect customer number provided."
            return @response
        end

        @is_clean = true
        @response
    end

    def check_hostname_param
        @is_clean = false
        @hostname = params[:hostname]

        if @hostname.nil?
            @response[:status] = -1
            @response[:msg] = "Hostname parameter missing."
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
        response.headers['Cache-Control'] = 'public, max-age=300'
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
            'cloudways_apache2_installed'       => 'apache2'
        }

        begin
            rpc_client = rpcclient('rpcutil', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.fact_filter "cloudways_customer", @customer_number
            rpc_client.timeout = @timeout
            rpc_client.progress = false
            f = service_facts.keys.zip(facts).flatten.compact.join(', ')
            print "facts = #{f}"
            rpc_response = rpc_client.get_facts(:facts => f)
            host_list = []
            rpc_response.each do |resp|
                unless resp[:data][:values].nil?

                    roles = []
                    # If role is standardweb, varnish can be toggled. Otherwise
                    # not.
                    toggle_varnish = false


                    # 1 = varnish is enabled
                    # 0 = varnish is disabled
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
                            toggle_varnish = true
                            varnish_enabled = resp[:data][:values]['cloudways_varnish_enabled']

                            if varnish_enabled
                                if varnish_enabled == "1"
                                    is_varnish_enabled = 1
                                    unless roles.include?('varnish')
                                        roles.push('varnish')
                                    end
                                elsif varnish_enabled == "0"
                                    is_varnish_enabled = 0
                                    unless roles.include?('varnish')
                                        roles.push('varnish')
                                    end
                                elsif varnish_enabled == "2"
                                    is_varnish_enabled = 2
                                    roles.delete('varnish')
                                end
                            else
                                # if varnish_enabled is nil, we set the value to 2.
                                is_varnish_enabled = 2
                                roles.delete('varnish')
                            end
                        else
                            toggle_varnish = false
                        end
                    rescue NoMethodError => e
                    end

                    host_list.push({:fqdn               => resp[:data][:values]['fqdn'], 
                                    :hostname           => resp[:data][:values]['hostname'], 
                                    :roles              => roles,
                                    :varnish_enabled    => is_varnish_enabled,
                                    :cw_roles           => cw_roles,
                                    :toggle_varnish     => toggle_varnish,
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
        response.headers['Cache-Control'] = 'public, max-age=300'
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



    #
    # Enable varnish.
    # 
    def varnish_enable
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('varnish', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.enable()

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    #
    # Disable varnish
    #
    def varnish_disable
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('varnish', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.disable()

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end
    
    #
    # Check varnish enable/disable status
    #
    def varnish_status
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('varnish', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.status()

            @response[:status] = rpc_response[0][:data][:status]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end
    

    #
    # Purge varnish cache. 
    #
    def varnish_purge_cache
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('varnish', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.purge_cache()

            @response[:status] = rpc_response[0][:data][:status]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


    #
    # Return total number of customer servers available on MCollective network.
    #
    def servers_count
        response.headers['Cache-Control'] = 'public, max-age=300'
        begin
            rpc_client = rpcclient('rpcutil', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            total_servers = rpc_client.ping().length()

            rpc_client.fact_filter("cloudways_customer", "00000")
            test_servers = rpc_client.ping().length()

            @response[:status] = 1
            @response[:servers_count] = total_servers - test_servers

        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end




    #
    # On demand backup. 
    #
    def backup_on_demand
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('backup', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.on_demand()

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    #
    # Schedule backup.
    # Takes 'frequency' input parameter.
    #
    def backup_scheduled
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        # We take a frequency parameter which should be a positive integer.
        begin 
            frequency = params[:frequency].to_i
        rescue Exception => e
            @response[:status] = -1
            @response[:msg] = "Frequency not set properly."
        end

        begin
            rpc_client = rpcclient('backup', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.schedule(:frequency => frequency)

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


    #
    # API to faciliate Application installation on servers.
    # Takes in a slew of manadatory arugments, namely:
    #   action, application, application_version, sys_user, sys_password, mysql_db_name,
    #   mysql_user, mysql_password, app_user, app_password, app_fqdn,
    #   customer_name, customer_email
    #   customer_number, hostname
    #
    def app_install
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        params_list = (
            'action',
            'application', 
            'application_version', 
            'sys_user', 
            'sys_password', 
            'mysql_db_name',
            'mysql_user', 
            'mysql_password', 
            'app_user', 
            'app_password', 
            'app_fqdn',
            'customer_name', 
            'customer_email'
        )

        @is_clean = true
        params_list.each |key| do 
            if not params.has_key?(key) or params[key].empty?
                @is_clean = false
                @response[:status] = -1
                @response[:msg] = "#{key} parameter missing or empty."
                return render :json => @response
            end
        end

        begin
            rpc_client = rpcclient('app_installer', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.install(
                :action                 => params[:action],
                :application            => params[:application], 
                :application_version    => params[:application_version], 
                :sys_user               => params[:sys_user], 
                :sys_password           => params[:sys_password], 
                :mysql_db_name          => params[:mysql_db_name],
                :mysql_user             => params[:mysql_user], 
                :mysql_password         => params[:mysql_password], 
                :app_user               => params[:app_user], 
                :app_password           => params[:app_password], 
                :app_fqdn               => params[:app_fqdn],
                :customer_name          => params[:customer_name], 
                :customer_email         => params[:customer_email]
            )

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end

    #
    # API call to resize disk.
    # Takes the following inputs:
    #   customer_number, hostname, device
    #
    def resize_disk
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        if not params.has_key?('device') or params['device'].empty?
            @response[:status] = -1
            @response[:msg] = "params parameter missing or empty."
            return render :json => @response
        end

        device = params[:device]

        begin
            rpc_client = rpcclient('app_installer', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.resize_disk(:device => device)

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


    #
    # This API adds a new CNAME.
    # It takes the following parameters:
    #   customer_number, hostname
    #   cname (must be without protocol prefix)
    #   server_fqdn (must be without protocol prefix)
    #   sys_user
    #
    def add_cname
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        cname = params[:cname]
        server_fqdn = params[:server_fqdn]
        sys_user = params[:sys_user]

        @is_clean = true

        if cname.nil?
            @response[:status] = -1
            @response[:msg] = "cname parameter missing or empty."
            @is_clean = false
        end

        if server_fqdn.nil?
            @response[:status] = -1
            @response[:msg] = "server_fqdn parameter missing or empty."
            @is_clean = false
        end

        if sys_user.nil?
            @response[:status] = -1
            @response[:msg] = "sys_user parameter missing or empty."
            @is_clean = false
        end

        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('app_installer', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.add_cname(:cname => cname,
                                                :server_fqdn => server_fqdn,
                                                :sys_user => sys_user)

            @response[:status] = rpc_response[0][:data][:status]
            @response[:response] = rpc_response[0][:data][:result]
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


end
