<?php

class AclComponent extends Object 
{
	
	/*
	 * Initialize Variables
	 * 
	 * These are used for different methods below
	 *
	 */
	
	//Setup class Item obj var
	var $Item = null;
	
	//Setup class Allow obj var
	var $Allow = null;
	
	//Setup .ini var
	var $conf = null;
	
	//Setup folder obj var
	var $folder = null;


	/* function initialize()
	 * 
	 * Setup Item and Allow classes
	 * Import Folder class
	 * setup conf var with ini data
	 * 
	 * Runs before controllers beforeFilter
	 */
	 
	function initialize(&$controller)
	{
		$this->Item = ClassRegistry::init('Item');
		$this->Allow = ClassRegistry::init('Allow');
		
		App::Import('Core', 'Folder', 'File');
		$this->folder =& new Folder();

		$this->conf = $this->parse_ini();
    }
	
	
	/* Function: check
	** Access: Public
	** Arguments:
	**     $auth = array of auth data passed from user session
	**     $url = url the user is accessing
	**     $action = action to check defaults to *
	**
	** Returns: True or False
	**
	*/
	 
	public function check($auth, $url, $action = '*')
	{
	
		//Setup return value to default to false
	   	$return = false;
		
		//get list of items from cache
        $data = $this->cache();
                        
        //get all group ids that the user belongs to                
        $groups = array();
        foreach($auth['User']['Group'] as $group){
        	$groups[] = $group['id'];
        }
        
        //get the full app path of the url
        $app_path = $this->conf['Main']['name'] . DS . $url;

		$location = $this->return_loc($app_path);
        //recurse through items and build list of allowed users and groups
    	$allowed = $this->find_allowed(
    		$data, 
    		$location, 
    		$app_path, 
    		array(
    			'return' => 'both', 
    			'field' => 'foreign_id', 
    			'found' => true,
    			'exit' => false,
    			'user_id' => $auth['User']['User']['id'],
    			'groups' => $groups
    		), 
    		array()
    	);
    	
    	//if item is ignored, allow user
        if($allowed['open']){
        	return true;
        }
        
        //if user is allowed, allow user
        if(array_key_exists('user', $allowed)){
        	if(!empty($allowed['user'])){
	        	return true;
			}
        }
        
        //if a group the user is in is allowed, allow user
        if(array_key_exists('group', $allowed)){
        	if(!empty($allowed['group'])){
	        	return true;
			}
        }
        
	    //return permission
	    return false;
			
	}
	
	/* Function: find_allowed
	** Access: Private
	** Arguments:
	**     $items = array of Items in ACL
	**     $location = array of items being accessed
	**     $name = defaulted to Null
	**     $options = array of options to include all of these are optional except return
	**         1) what field to return ('field')
	**         2) groups, users, both ('return')
	**         3) user_id ('user_id')
	**         4) available apps array ('app')
	**         5) return if not found ('found')
	**         6) pass allowed groups ('groups')
	**		   7) return on find, boolean to return immediately when found ('exit')
	**     $return = blank array
	**
	** Returns: Array of data requested
	**
	** Recursive function which returns a variety of results based on options
	**
	*/
	 
	private function find_allowed($items, $location = array(), $uri = null, $options = array('return' => 'both', 'field' => 'foreign_id', 'return' => false), $return = array()){
	
		if(isset($options['continue'])){
			if(array_key_exists('url', $items)){
				if($items['url'] === $uri){
					$return['open'] = false;
				}
			}
			
			if(array_key_exists('Allow', $items)){
				if(in_array($items['url'], $location) || ($options['return'] === 'app' && in_array($this->get_app_name($items['url']), $options['app'])) || (isset($options['app']) && $this->get_app_name($items['url']) === $options['app'])){
					$new_allows = $this->return_allowed($items['Allow'], $options['return'], $options['field'], $options['groups'], $options['user_id'], $options['superadmin']);
					if($options['return'] === 'app'){
						if(!empty($new_allows) || $options['superadmin']){
							$return['app'][] = $this->get_app_name($items['url'], false);
						}
					}
					if(array_key_exists('group', $new_allows)){
						if(!array_key_exists('group', $return)){
							$return['group'] = array();
						}
						$return['group'] = array_merge($return['group'], $new_allows['group']);
					}
					if(array_key_exists('user', $new_allows)){
						if(!array_key_exists('user', $return)){
							$return['user'] = array();
						}
						$return['user'] = array_merge($return['user'], $new_allows['user']);
					}
				}
			}
			foreach($items as $item){
				if(is_array($item)){
					$return = $this->find_allowed($item, $location, $uri, $options, $return);
				}

			}
		}
		
		if(!array_key_exists('continue', $options)){
			if(is_array($items) && array_key_exists('Item', $items)){
				if($items['Item']['name'] === $this->conf['Main']['name']){	
					$new_allows = $this->return_allowed($items['Allow'], $options['return'], $options['field'], $options['groups'], $options['user_id']);
					
					$return['superuser'] = $new_allows;
					
					if(!empty($new_allows)){
						$options['superadmin'] = true;
					} else {
						$options['superadmin'] = false;
					}
								
					$return = array_merge($new_allows, $return);
					if(!$options['exit']){
						$options['continue'] = true;
					}
					if(!array_key_exists('open', $return)){
						$return['open'] = true;
					}
					
					$return = $this->find_allowed($items['Children'], $location, $uri, $options, $return);
					
				}
			}
		}
	
		return $return;	
		
	}

	private function return_allowed($allows, $return, $key, $groups, $user_id, $superuser = false){
		$result = array();
		foreach($allows as $allow){
			if($return === 'both' || $return === 'groups' || $return === 'app'){
				if($allow['model'] === 'Group' && (in_array($allow[$key], $groups) || $superuser)){
					$result['group'][] = $allow[$key];
				}
			}
			
			if($return === 'both' || $return === 'users' || $return === 'app'){
				if($allow['model'] === 'User' && $allow[$key] === $user_id){
					$result['user'][] = $allow[$key];
				}
			}
		}
		
		return $result;
		
	}

	private function get_app_name($url, $path = true){
		$app = explode('/', $url);
		
		return ($path)? $this->conf['Main']['name'] . DS . $app[1] : Inflector::underscore($app[1]);
	
	}

	/* Function: return_loc
	** Access: Private
	** Arguments:
	**     $app_path = path of url
	**
	** Returns: Array of location data
	**
	*/

	private function return_loc($app_path){
	
		//explode url into array of items
	    $location = explode(DS, $app_path);
        
        //take expanded url and tack full path on the front of each        
        $output = null;
        for($i = 0; $i < count($location); $i++){
        	if($i != 0){
        		$output .= DS;
        	}
        	$output .= $location[$i];
        	$location[$i] = $output;
     	}
     	
     	return $location;

	}

	/* Function: getGroups
	** Access: public
	** Arguments:
	**     $user_id = id of requested user
	**     $app = name of plugin you are looking for
	**
	** Returns: Array of group names for user for requested plugin
	**
	*/
	
	public function getGroups($user_id, $app){
		
		//set app to be inflected correctly
		$app = Inflector::camelize($app);
		$app = $this->conf['Main']['name'] . DS . $app;
		
		//build array from cache
		$items = $this->cache();
		
		//find all of this users groups
		$this->Allow->User->Behaviors->attach('Containable');
		$usersGroups = $this->Allow->User->find('first', array(
			'conditions' => array(
				'User.id' => $user_id
			),
			'contain' => array(
				'Group'
			)
		));
		
		//make array of only group id's
		$returnGroups = array();
		if(!empty($usersGroups['Group'])){
			foreach($usersGroups['Group'] as $item){
				
				$returnGroups[] = $item['id'];
				
			}
		}
		
		//Descend through items and return allowed groups
		$groups = $this->find_allowed(
			$items, 
			array(), 
			null, 
			array(
				'user_id' => null,
				'exit' => false,
				'return' => 'groups',
				'field' => 'foreign_id',
				'app' => $app,
				'groups' => $returnGroups
			), 
			array()
		);
		
		if(isset($groups['group'])){
			$groups['group'] = array_unique($groups['group']);
		}
		
		$groups = (array_key_exists('group', $groups['superuser']))? array_diff($groups['group'], $groups['superuser']['group']) : $groups['group'];
				
		$return = $this->Allow->Group->find('list', array(
			'conditions' => array(
				'id' => $groups
			)
		));
				
		return $return;
		
	}
	
	/* Function: getApps
	** Access: public
	** Arguments:
	**     $user_id = id of requested user
	**
	** Returns: Array of app names for user
	**
	*/
	
	public function getApps($user_id){
		//prepare apps array
		$apps = array();
		
		//Find all enabled applications that are plugins
		$applications = ClassRegistry::init('Application');
		$all = $applications->find('list', array(
			'conditions' => array(
				'NOT' => array(
					'plugin_name' => ''
				)
			),
			'fields' => array('id', 'plugin_name')
		));
		
		$acl_apps = $this->conf['Plugins']['name'];
		
		foreach($all as $i => $app){
			$app = Inflector::camelize($app);
			
			if(in_array($app, $acl_apps)){
				$all[$i] = $this->conf['Main']['name'] . DS . $app;
			} else {
				$apps[] = Inflector::underscore($app);
			}
			
		}
		//return cache
		$items = $this->cache();
		
		//find all of this users groups
		$this->Allow->User->Behaviors->attach('Containable');
		$usersGroups = $this->Allow->User->find('first', array(
			'conditions' => array(
				'User.id' => $user_id
			),
			'contain' => array(
				'Group'
			)
		));
		
		//make array of only group id's
		$returnGroups = array();
		if(!empty($usersGroups['Group'])){
			foreach($usersGroups['Group'] as $item){
				
				$returnGroups[] = $item['id'];
				
			}
		}
		
		//descend through items and find allowed groups for this user
		$allowed = $this->find_allowed($items, array(), null, array('field' => 'foreign_id', 'user_id' => null, 'exit' => false, 'groups' => $returnGroups, 'app' => $all, 'return' => 'app'));
		
		//strip main app name and return apps array
		if(!empty($allowed['app'])){
			$allowed['app'] = array_unique($allowed['app']);
			$allowed = $allowed['app'];
			$strip = $this->conf['Main']['name'] . "\\" . DS;
			
			foreach($allowed as $app){
				$apps[] = Inflector::underscore(preg_replace("/$strip/i", '', $app));
			}
		}
				
		return $apps;

	}

	/* Function: cache
	** Access: private
	** Arguments:
	**     $update = boolean on whether to force a rebuild
	**
	** Returns: Array items and allows
	**
	*/
	
	public function cache($update = false) 
	{
		//if cache update is forced, delete current cache
		if($update){
			Cache::delete('allows');
		}
		
		//check cache
	    $allows = Cache::read('allows');
	    
	    //build array of all items by parent => children => children
	    if($allows === false || empty($allows)){
    		$allows = $this->Item->find('first', array(
    		  'conditions' => array(
    		  	  'Item.name' => $this->conf['Main']['name']
    		  ),
    		  'recursive' => 4,
    		  'contain' => array(
    		  	'Allow',
    		  	'Children',
    		  	'Children.Allow', 
    		  	'Children.Children',
    		  	'Children.Children.Allow'
    		  )
    		  
            ));
            Cache::write('allows', $allows);
        }
		return $allows;
	}

	public function dry_run(){
	
		
		//set easy call variable for main app name
		$parent = $this->conf['Main']['name'];
		$plugins = $this->conf['Plugins']['name'];
		$Group = ClassRegistry::init('Group');
		$groups = $Group->find('list');
		
		$ignores = array();
		if(isset($this->conf['Ignore'])){
		
			if(array_key_exists('action', $this->conf['Ignore'])){
				
				foreach($this->conf['Ignore']['action'] as $action){
				
					$action =  ltrim($action, '/');
					$item = explode(DS, $action);
					switch($item[0]){
						
						case $parent:
							$ignores[] = addcslashes($action, '/');
							break;
						
						case in_array($item[0], $plugins):
							$ignores[] = addcslashes($parent . DS . $action, '/');
							break;
						
						default:
							$ignores[] = addcslashes($parent . '.*' . DS . $action, '/');
					}
				
				}
				
			}
			
			if(array_key_exists('controller', $this->conf['Ignore'])){
			
				foreach($this->conf['Ignore']['controller'] as $controller){
					
					$controller = ltrim($controller, '/');
					$item = explode(DS, $controller);
					switch($item[0]){
					
						case $parent:
							$ignores[] = addcslashes($controller, '/');
							break;
							
						case in_array($item[0], $plugins):
							$ignores[] = addcslashes($parent . DS . $controller, '/');
							break;
						
						default:
							$ignores[] = addcslashes($parent . '.*' . DS . $controller, '/');
					
					}
					
				}
			
			}
		
		}
		
		//rebuild cache of items
		$data = $this->cache(true);
	
		//retrieve all URL's from data
		$urls = (!empty($data))? $this->get_urls($data, array()) : array();
		
		$finds = array();
		foreach($ignores as $ig){
			$result = $this->Array_Search_Preg($ig, $urls);
			if($result){
				$finds['remove'] = array_merge($result, $finds);
			}
		}
		
		//Take ini as written and make array
		$items = $this->build_ini(false);
		
		$finds['new'] = array_diff($items, $urls);	
		
		
		if(!empty($finds['new'])){
			//Build auto adds
			$prefixes = Configure::read('Routing.prefixes');
			
			$groups = $this->Allow->Group->find('list');
			
			$plugin_group = array();
			foreach($groups as $group){
				$prefix = end(explode('_', $group));
				if(in_array($prefix, $prefixes)){
					$plugin_group[] = $group;
				}
			}
			
			foreach($plugin_group as $item){
				
				$item_arr = explode('_', $item);
				$prefix = array_pop($item_arr);
				
				$plugin = Inflector::camelize(implode('_', $item_arr));
				
				$needle = addcslashes($parent . DS . $plugin . DS . '.*' . DS . $prefix . '_.*', DS);
				$new_groups = $this->Array_Search_Preg($needle, $finds['new'], array());
				
				if(!empty($new_groups)){
					$finds['add_group'][$plugin][$prefix] = $new_groups;
				}
				
			}
		} else {
			unset($finds['new']);
		}		
		return $finds;
			
	}
	
	private function Array_Search_Preg($find, $in_array, $keys_found=Array()){ 
	    if( is_array( $in_array ) ){ 
	        foreach( $in_array as $key=> $val ) { 
	            if( is_array( $val ) ) { 
	            	$this->Array_Search_Preg( $find, $val, $keys_found ); 
	            } else {
	                if( preg_match( '/'. $find .'/', $val ) ){ 
	                	$keys_found[] = $val; 
	                }
	            } 
	        } 
	        return $keys_found; 
	    } 
	    return false; 
	}
	
	public function update($updates = array()){
		
		$error = array();
		if(isset($updates['remove'])){
			foreach($updates['remove'] as $remove){
				$id = null;
				$id = $this->Item->field('id', array(
						'url' => $remove
					)
				);
				
				if(!$this->Item->delete($id)){
					$error[] = "Item $remove did not get removed";
				};
				
			}
		}
		
		if(isset($updates['new'])){
			foreach($updates['new'] as $new){
				
				$data = array();
							
				$location = explode(DS, $new);
				$data['Item']['name'] = array_pop($location);
				
				$parent = implode(DS, $location);
				
				$data['Item']['url'] = $new;
				$parent_data = $this->Item->find('first', array(
					'conditions' => array(
						'Item.url' => $parent
					)
				));
				
				if(!empty($parent_data)){
					$data['Item']['parent'] = $parent_data['Item']['name'];
					$data['Item']['parent_id'] = $parent_data['Item']['id'];
				}
																
				$this->Item->create();
				if(!$this->Item->save($data)){
					$error[] = "Item $new did not get added";
				}
			}
		}
		
		if(isset($updates['add_group'])){
			foreach($updates['add_group'] as $plugin => $groups){
				if(!empty($groups)){
					foreach($groups as $group => $actions){
						if(!empty($actions)){
							foreach($actions as $action){
								$name = Inflector::underscore($plugin . '_' . $group);
								$result = $this->Allow->Group->find('first', array(
									'conditions' => array(
										'Group.name' => $name
									)
								));
								
								$item = $this->Item->find('first', array(
									'conditions' => array(
										'Item.url' => $action
									)
								));
								
								$data['Allow'] = array(
									'item_id' => $item['Item']['id'],
									'foreign_id' => $result['Group']['id'],
									'model' => 'Group'
								);
								
								$this->Allow->create();
								if(!$this->Allow->save($data)){
									$error[] = "Group $name did not get added to $action allows";
								}
							}
						}												
					}
				}
			}
		
		}
		
		if(empty($error)){
			return true;
		} else {
			return $error;
		}			
	}

	/* Function: get_urls
	** Access: private
	** Arguments:
	**     $data = array of data to retrieve urls from
	**	   $urls = array of returnable urls
	** Returns: Array of urls
	**
	*/

    private function get_urls($data, $urls){
    
    	//loop through items to find urls
    	foreach($data as $key => $item){
    		//if item is an array
    		if(is_array($item)){
    			//loop through it and if url key is in there push url onto return array
    			foreach($item as $i => $e){
    				if($i === 'url' && !in_array($e, $urls)){
    					$urls[] = $e;
    				}
    				//otherwise recurse through array
    				if(is_array($e)){
    					$urls = $this->get_urls($e, $urls);
    				}
    			}
    		//if key exists push item onto return array
    		} elseif($key === 'url' && !in_array($item, $urls)){
    			$urls[] = $item;
    		}
		}    	
		
		//return urls
    	return $urls;
    	
    }
    
	/* Function: build_ini
	** Access: private
	** Arguments:
	**    $nested = boolean as to whether nest actions or have flat url array
	** Returns: Array of urls
	**
	*/
	
	
	private function build_ini($nested = false, $ignores = array()) {
		
		//build array of controllers in portal and plugins
		$parent = $this->conf['Main']['name'];
		$plugins = $this->conf['Plugins']['name'];
		
		//get main app controllers
		$controllers = App::objects('controller', false, false);
				
		//get all controller ignores
		$ignores = $this->conf['Ignore']['controller'];
		$ignores[] = 'App';
		
		//strip Portal/ if present
		if(!empty($ignores)){
			foreach($ignores as $i => $ignore){
				$ignores[$i] = str_replace($parent . DS, '', $ignore);
			}
		}
		
		//get list of controllers not ignored
		$controllers = array_diff($controllers, $ignores);
		if($nested){
			$paths[$parent] = array();
		} else {
			$paths[] = $parent;
		}
			
		foreach($controllers as $controller){
			
			App::Import('Controller', $controller);
			$parent_methods = get_class_methods(get_parent_class($controller.'Controller'));
			$methods = get_class_methods($controller . 'Controller');
			
			$methods = ($methods)? array_diff($methods, $parent_methods) : array();
			if($nested){
				$paths[$parent][$controller] = array();
			} else {
				$paths[] = $parent . DS . $controller;
			}
					
			foreach($methods as $method){
				if($nested){
					$paths[$parent][$controller][] = $method;
				} else {
					$paths[] = $parent . DS . $controller . DS . $method;
				}
			}
		
		}
		
		foreach($plugins as $plugin){
			
			if($nested){
				$paths[$parent][$plugin] = array();
			} else {
				$paths[] = $parent . DS . $plugin;
			}			
			$controllers = App::objects('controller', App::pluginPath($plugin) . DS . 'controllers', false);
			
			foreach($controllers as $controller){
			
				$file_path = App::pluginPath($plugin) . DS . 'controllers' . DS . Inflector::underscore($controller) . '_controller.php';
				App::Import('Controller', $plugin . '.' . $controller, array('file' => $file_path));
					
				$parent_methods = get_class_methods(get_parent_class($controller . 'Controller'));
				$methods = get_class_methods($controller.'Controller');
				$methods = array_diff($methods, $parent_methods);
				
				if($nested){
					$paths[$parent][$plugin][$controller] = array();
				} else {
					$paths[] = $parent . DS . $plugin . DS . $controller;
				}
												
				foreach($methods as $method){
					if(!preg_match('/^_/',$method)){
						if($nested){
							$paths[$parent][$plugin][$controller][] = $method;
						} else {
							$paths[] = $parent . DS . $plugin . DS . $controller . DS . $method;
						} 
					}
				}
				
			}
			
		}
		
		return $paths;		
		
	}     

    function getControllers() {
        
        $paths = array();
        
        $paths[$this->conf['Main']['name']] = CONTROLLERS;
        
        foreach($this->conf['Plugins']['name'] as $plugin){
        
            $paths[$plugin] = PLUGINS . Inflector::underscore($plugin) . DS . 'controllers' . DS;
        
        }
        
        $controllerClasses = array();
        foreach($paths as $app => $path){
            
            $array = $this->folder->tree($path);
            
            foreach($array[1] as $key => $item){
                if(stristr($item, 'components')){
                    unset($array[1][$key]);
                }
            }
            
            if($app == $this->conf['Main']['name']){
                $controllerClasses[$app] = $array[1];
            } else {
                $controllerClasses[$this->conf['Main']['name']][$app] = $array[1];
            }    
        }        
        
        return $controllerClasses;
    }

	/*
	 * @public function parse_ini
	 * We are creating a place holder function to do parse_ini_file so that we
	 * can easily expand upon this action later as the ini file grows
	 * 
	 */ 
	
	private function parse_ini()
	{
		$acl = parse_ini_file(APP . 'acl.ini', true);
		
		return $acl;
		
	}

}

?>