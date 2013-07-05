# Be sure to restart your server when you modify this file.

# Your secret key for verifying cookie session data integrity.
# If you change this key, all old sessions will become invalid!
# Make sure the secret is at least 30 characters and all random, 
# no regular words or you'll be exposed to dictionary attacks.
ActionController::Base.session = {
  :key         => '_dashboard_session',
  :secret      => '673826d7490ee9cdd0e6152772d82a737ab4c333932b0b24dd98eb283c5c6e84fc9c97a4a5f17b00a5ea1b1470be0d57396d8fd49703f3bdb869b3a7e8bd9cf3'
}

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# ActionController::Base.session_store = :active_record_store
