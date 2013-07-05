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
    end
end
