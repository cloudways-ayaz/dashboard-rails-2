class CreateRequestLogs < ActiveRecord::Migration
    def self.up
        create_table :request_logs do |t|
            t.string :ip
            t.text :server_headers
            t.text :post_data
            t.integer :customer_number
            t.timestamp :time

            t.timestamps
        end
    end

    def self.down
        drop_table :request_logs
    end
end
