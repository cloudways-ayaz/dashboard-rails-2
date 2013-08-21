module ServiceHelper
    class ParamsVerifier
        def initialize
            @params_dict = JSON.parse(File.open(File.join(Rails.root, 'lib', 'assets', 'params.json')).read)
        end

        def get_service(service_name)
            return @params_dict["service"][service_name]
        end

        def get_customer_number(customer_number)
            return @params_dict["customer_number"][customer_number]
        end


        def verify_auth(username, password)
            if @params_dict["auth"]["user"] == username && @params_dict["auth"]["pass"] == password
                return true
            end
            return false
        end

        def add_customer(customer_number, customer_number_hash)
            unless @params_dict["customer_number"].has_key?(customer_number_hash)
                @params_dict["customer_number"][customer_number_hash] = customer_number
                return true
            end
            return false
        end

        def write_params_to_file
            fh = File.open(File.join(Rails.root, 'lib', 'assets', 'params.json'), 'w')
            JSON.dump(@params_dict, fh)
            fh.close()
        end
    end
end
