
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
    around_filter :global_request_logging

    #
    # Log the request in RequestLog table.
    # 
    def global_request_logging
        keys = ['SERVER_NAME', 'REQUEST_PATH', 'HTTP_USER_AGENT',
                'REMOTE_HOST', 'SERVER_PROTOCOL', 'SERVER_SOFTWARE',
                'REMOTE_ADDR', 'PATH_INFO', 'SCRIPT_NAME',
                'HTTP_VERSION', 'REQUEST_URI', 'REQUEST_METHOD',
                'QUERY_STRING', 'GATEWAY_INTERFACE', 'HTTP_HOST',
                'HTTP_ACCEPT']
        headers_dict = {}
        keys.each do |k|
            headers_dict[k] = request.headers[k]
        end

        customer_number = params[:customer_number]
        unless customer_number.nil?
            customer_number = @params_verifier.get_customer_number(customer_number)
        end

        begin
            request_log = RequestLog.new(:ip              => request.remote_ip,
                                         :server_headers  => JSON.dump(headers_dict),
                                         :post_data       => JSON.dump(params),
                                         :customer_number => customer_number
                                        )
            request_log.save
        rescue Exception => e
            logger.info("Exception when trying to save RequestLog: #{e}")
        end
        yield
    end

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
        @ping_timeout = 10
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

    #
    # Fetch status of more than one services. 
    #   @customer_number
    #   @hostname
    #   @service_list (comma-separated list of hashed service names)
    #
    def multi_status
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        service_list = params[:service_list]
        if service_list.nil? or service_list.empty?
            @response[:status] = -1
            @response[:response] = "Customer number parameter missing."
            return render :json => @response
        end

        service_list = service_list.split(',')
        # This will contain the service names in plain-text.
        _service_list = []
        service_list.each do |service|
            service = service.strip
            service_name = @params_verifier.get_service(service)
            if service_name.nil?
                @response[:status] = -1
                @response[:response] = "Incorrect service name provided: #{service_name}"
                return render :json => @response
            end
            _service_list.push(service_name)
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

            rpc_response = rpc_client.multi_status(:service_list => _service_list.join(','))
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
            @response[:response] = "API error: #{e}"
        end


        # Check whether varnish is enabled or disabled.
        if _service_list.include?('varnish')
            begin
                rpc_client = rpcclient('varnish', {:exit_on_failure => false})
                rpc_client.verbose = false
                rpc_client.progress = false
                rpc_client.timeout = @timeout

                rpc_client.fact_filter "cloudways_customer", @customer_number
                rpc_client.identity_filter @hostname

                rpc_response = rpc_client.status()

                @response[:response]["status"]["varnish_enabled"] = rpc_response[0][:data][:status]
            rescue Exception => e
                @response[:status] = -2
                @response[:response] = "API error: #{e}"
            end
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

        # Longer timeout, 15 minutes.
        timeout = 900

        begin
            rpc_client = rpcclient('backup', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.on_demand()

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
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

        frequency = params[:frequency]
        # We take a frequency parameter which should be a positive integer.
        begin 
            params[:frequency].to_i
        rescue Exception => e
            @response[:status] = -1
            @response[:msg] = "Frequency not set properly."
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
            rpc_response = rpc_client.schedule(:frequency => frequency)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end


    #
    # API to faciliate Application installation on servers.
    # Takes in a slew of manadatory arugments, namely:
    #   app_action, application, application_version, sys_user, sys_password, mysql_db_name,
    #   mysql_user, mysql_password, app_user, app_password, app_fqdn,
    #   customer_name, customer_email
    #   customer_number, hostname
    #
    #   if app_action is 'install', it will install the application.
    #   if it is 'uninstall', it will uninstall the given application.
    #
    def app_install
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        # We want a longer timeout, 15 minutes long.
        timeout = 900

        params_list = [
            'app_action',
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
        ]

        @is_clean = true
        params_list.each do |key|
            if not params.has_key?(key) or params[key].empty?
                @is_clean = false
                @response[:status] = -1
                @response[:response] = "#{key} parameter missing or empty."
                return render :json => @response
            end
        end


        # Check to see if @hostname is alive on network so as to return with an
        # error instead of waiting 15 minutes for the call to timeout otherwise.
        alive_flag = true
        begin
            r_client = rpcclient('rpcutil', {:exit_on_failure => false})
            r_client.verbose = false
            r_client.progress = false
            r_client.timeout = @ping_timeout

            r_client.fact_filter "cloudways_customer", @customer_number
            r_client.identity_filter(@hostname)
            r = r_client.ping()
            if r.nil? or r.empty?
                @response[:status] = -1
                @response[:response] = "#{@hostname} is not alive on network."
                alive_flag = false
            end

        rescue Exception => e
            @response[:status] = -2
            @response[:response] = "API error: #{e}"
            alive_flag = false
        end

        unless alive_flag
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('app_installer', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.install(
                :action                 => params[:app_action],
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

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:response] = "API error: #{e}"
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

        # We want a longer timeout, 15 minutes long.
        timeout = 900

        device = params[:device]

        begin
            rpc_client = rpcclient('app_installer', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = timeout

            unless @customer_number.nil?
                rpc_client.fact_filter "cloudways_customer", @customer_number
            end

            unless @hostname.nil?
                rpc_client.identity_filter @hostname
            end
            rpc_response = rpc_client.resize_disk(:device => device)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
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
    #   old_cname (optional, but when present, it should be the cname to remove)
    #
    def add_cname
        @response = check_customer_number_and_hostname_params
        unless @is_clean
            return render :json => @response
        end

        cname = params[:cname]
        server_fqdn = params[:server_fqdn]
        sys_user = params[:sys_user]
        application = params[:application]
        old_cname = params[:old_cname] || ''

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

        if application.nil?
            @response[:status] = -1
            @response[:msg] = "application parameter missing or empty."
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
                                                :sys_user => sys_user,
                                                :application => application,
                                                :old_cname => old_cname)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response
    end



    #
    # Remove given server from Sensu, so that its monitoring data is 
    # deleted and the server is no longer monitored.
    #   Input: server_name (this should be the subdomain part of the server
    #                       FQDN)
    #          hostname  (this should be the fixed address of the sensu server)
    def sensu_remove
        @response = check_hostname_param
        unless @is_clean
            return render :json => @response
        end

        server_name = params[:server_name]
        if server_name.nil?
            @response[:status] = -1
            @response[:msg] = "server_name parameter missing or empty."
            @is_clean = false
        end

        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('sensu', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            rpc_client.identity_filter @hostname

            rpc_response = rpc_client.remove(:server_name => server_name)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:msg] = "API error: #{e}"
        end

        render :json => @response

    end



    #
    # Adds given IP into Shorewall's rules.
    # @params: hostname
    #          ip
    #          server_fqdn
    #
    def shorewall_add_ip 
        @response = check_hostname_param
        unless @is_clean
            return render :json => @response
        end

        ip = params[:ip]
        if ip.nil?
            @response[:status] = -1
            @response[:response] = "ip parameter missing or empty."
            @is_clean = false
        end

        server_fqdn = params[:server_fqdn]
        if server_fqdn.nil?
            @response[:status] = -1
            @response[:response] = "server_fqdn parameter missing or empty."
            @is_clean = false
        end

        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('shorewall', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            rpc_client.identity_filter @hostname

            rpc_response = rpc_client.add_ip(:ip => ip, :server_fqdn => server_fqdn)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:response] = "API error: #{e}"
        end

        render :json => @response

    end

    #
    # Removes given IP from Shorewall's rules.
    # @params: hostname
    #          ip
    #          server_fqdn
    #
    def shorewall_remove_ip 
        @response = check_hostname_param
        unless @is_clean
            return render :json => @response
        end

        ip = params[:ip]
        if ip.nil?
            @response[:status] = -1
            @response[:response] = "ip parameter missing or empty."
            @is_clean = false
        end

        server_fqdn = params[:server_fqdn]
        if server_fqdn.nil?
            @response[:status] = -1
            @response[:response] = "server_fqdn parameter missing or empty."
            @is_clean = false
        end

        unless @is_clean
            return render :json => @response
        end

        begin
            rpc_client = rpcclient('shorewall', {:exit_on_failure => false})
            rpc_client.verbose = false
            rpc_client.progress = false
            rpc_client.timeout = @timeout

            rpc_client.identity_filter @hostname

            rpc_response = rpc_client.remove_ip(:ip => ip, :server_fqdn => server_fqdn)

            if rpc_response.length > 0
                @response[:status] = rpc_response[0][:data][:status]
                @response[:response] = rpc_response[0][:data][:result]
            else
                @response[:status] = -1
                @response[:response] = "No nodes discovered."
            end
        rescue Exception => e
            @response[:status] = -2
            @response[:response] = "API error: #{e}"
        end

        render :json => @response

    end



    def host_ping
        hostname = request[:hostname]
        if hostname.nil? 
            @response[:status] = -1
            @response[:response] = "hostname parameter missing"
        end

        begin
            r_client = rpcclient('rpcutil', {:exit_on_failure => false})
            r_client.verbose = false
            r_client.progress = false
            r_client.timeout = @ping_timeout

            r_client.identity_filter(hostname)
            r = r_client.ping()
            if r.nil? or r.empty?
                @response[:status] = -1
                @response[:response] = "#{hostname} is not alive on network."
            else
                @response[:status] = 0
                @response[:response] = "Pong"
            end

        rescue Exception => e
            @response[:status] = -2
            @response[:response] = "API error: #{e}"
        end
        render :json => @response
    end

end
