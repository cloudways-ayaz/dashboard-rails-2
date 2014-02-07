ActionController::Routing::Routes.draw do |map|
  # The priority is based upon order of creation: first created -> highest priority.

  # Sample of regular route:
  #   map.connect 'products/:id', :controller => 'catalog', :action => 'view'
  # Keep in mind you can assign values other than :controller and :action

  # Sample of named route:
  #   map.purchase 'products/:id/purchase', :controller => 'catalog', :action => 'purchase'
  # This route can be invoked with purchase_url(:id => product.id)

  # Sample resource route (maps HTTP verbs to controller actions automatically):
  #   map.resources :products

  # Sample resource route with options:
  #   map.resources :products, :member => { :short => :get, :toggle => :post }, :collection => { :sold => :get }

  # Sample resource route with sub-resources:
  #   map.resources :products, :has_many => [ :comments, :sales ], :has_one => :seller
  
  # Sample resource route with more complex sub-resources
  #   map.resources :products do |products|
  #     products.resources :comments
  #     products.resources :sales, :collection => { :recent => :get }
  #   end

  # Sample resource route within a namespace:
  #   map.namespace :admin do |admin|
  #     # Directs /admin/products/* to Admin::ProductsController (app/controllers/admin/products_controller.rb)
  #     admin.resources :products
  #   end

  # You can have the root of your site routed with map.root -- just remember to delete public/index.html.
  # map.root :controller => "welcome"

  # See how all your routes lay out with "rake routes"

  # Install the default routes as the lowest priority.
  # Note: These default routes make all actions in every controller accessible via GET requests. You should
  # consider removing or commenting them out if you're using named routes and resources.
  map.connect ':controller/:action/:id'
  map.connect ':controller/:action/:id.:format'


  map.connect 'service/status',         :controller => 'service', :action => 'status',              :via => :get
  map.connect 'service/stop',           :controller => 'service', :action => 'stop',                :via => :get
  map.connect 'service/start',          :controller => 'service', :action => 'start',               :via => :get
  map.connect 'service/restart',        :controller => 'service', :action => 'restart',             :via => :get
  map.connect 'service/multi_status',   :controller => 'service', :action => 'multi_status',        :via => :get

  map.connect 'service/get_host_list',  :controller => 'service', :action => 'get_host_list',       :via => :get
  map.connect 'service/add_customer',   :controller => 'service', :action => 'add_customer',        :via => :post


  #
  # items URL
  # 
  map.connect 'dashboard/get_items',    :controller => 'service', :action => 'get_dashboard_items',  :via => :get


  #
  # varnish enable and disable
  #
  map.connect 'varnish/enable',         :controller => 'service', :action => 'varnish_enable',      :via => :get
  map.connect 'varnish/disable',        :controller => 'service', :action => 'varnish_disable',     :via => :get
  map.connect 'varnish/status',         :controller => 'service', :action => 'varnish_status',      :via => :get
  map.connect 'varnish/purge_cache',    :controller => 'service', :action => 'varnish_purge_cache', :via => :get


  #
  # servers count
  #
  map.connect 'servers/count',          :controller => 'service', :action => 'servers_count',       :via => :get


  #
  # Backup URLs
  #
  map.connect 'backup/on_demand',       :controller => 'service', :action => 'backup_on_demand',    :via => :get
  map.connect 'backup/scheduled',       :controller => 'service', :action => 'backup_scheduled',    :via => :get
  map.connect 'backup/restore',         :controller => 'service', :action => 'backup_restore',      :via => :get
  map.connect 'backup/status',          :controller => 'service', :action => 'backup_status',       :via => :get
  map.connect 'backup/delete',          :controller => 'service', :action => 'backup_delete',       :via => :get
  map.connect 'backup/rollback',        :controller => 'service', :action => 'backup_rollback',     :via => :get
  map.connect 'backup/exists',          :controller => 'service', :action => 'backup_exists',       :via => :get

  #
  # App installation URLs
  #
  map.connect 'app/install',            :controller => 'service', :action => 'app_install',         :via => :get
  map.connect 'app/uninstall',          :controller => 'service', :action => 'app_install',         :via => :get
  map.connect 'app/status',             :controller => 'service', :action => 'app_status',          :via => :get

  map.connect 'app/resize_disk',        :controller => 'service', :action => 'resize_disk',         :via => :get

  map.connect 'app/add_cname',          :controller => 'service', :action => 'add_cname',           :via => :get

  #
  # Sensu URLs
  #
  map.connect 'sensu/remove',          :controller => 'service', :action => 'sensu_remove',       :via => :get

  #
  # Shorewall URLs
  #
  map.connect 'shorewall/add_ip',      :controller => 'service', :action => 'shorewall_add_ip',     :via => :get
  map.connect 'shorewall/remove_ip',   :controller => 'service', :action => 'shorewall_remove_ip',  :via => :get


  # SIAB URLs
  map.connect 'siab/add_ip',      :controller => 'service', :action => 'siab_add_ip',     :via => :get
  map.connect 'siab/remove_ip',   :controller => 'service', :action => 'siab_remove_ip',  :via => :get


  #
  # Ping URL
  map.connect 'host/ping',             :controller => 'service', :action => 'host_ping',            :via => :get
  map.connect 'host/alive',            :controller => 'service', :action => 'host_alive',           :via => :get

end
