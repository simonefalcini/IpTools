<?php

namespace simonefalcini\IpTools;

use Yii;
use \DeviceDetector\DeviceDetector;
use \DeviceDetector\Parser\Device\DeviceParserAbstract;
use \Detection\MobileDetect;

class IpTools {

	const ASN_BOT_LIST = [
		'AS14230',			// INVOLTA	
		'AS1423',			// CARSON-RTCA
		'AS34010',			// YAHOO-IRD
		'AS8100','AS62639',	// Quadranet
		'AS26101',			// Yahoo
		'AS18978',			// Enzu Inc
		'AS16276',			// OVH
		'AS26832',			// Rica Web Services
		'AS16724',			// WOW Datacenter
		'AS46664',			// Volumedrive
		'AS6921',			// Arachnitec
		'AS12876',			// Online S.A.S.
		'AS4134',			// Chinanet		
		'AS8001', 			// Net Access Corporation
		'AS31863',			// Centrilogic
		'AS53667',			// FranTech Solutions
		'AS54290',			// Hostwinds LLC.
		'AS62638', 			// Query Foundry, LLC
		'AS61440',			// Digital Energy Technologies Chile SpA
		'AS8075',			// Bing
		'AS15169','AS19527','AS36040','AS36492','AS395973','AS43515','AS36384'			// GOOGLE
		]; //,'AS53667','AS6921','AS62638']; // Vodafone 'AS30722'
	
	public static function getIp() {
		if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		    if (self::ip_is_private($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		        $ip = $_SERVER['REMOTE_ADDR'];
		    }
		    else {
		        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		    }
		}
		else {
		    $ip = $_SERVER['REMOTE_ADDR'];
		}
		if ($ip=='127.0.0.1' || $ip=='::1') {
		    $ip = '5.168.51.191';
		}
		$ipblocks = explode(',',$ip);

		foreach($ipblocks as $ip) {
			$ip = trim($ip);
			if (!self::ip_is_private($ip)) {
				return $ip;
			}
		}

		return null;
	}	

	public static function getGeo($ip=null) {
		if (!isset($ip)) {
			$ip = self::getIp();
		}
		$db = self::getDbName('country');
	    if (!empty($db)) {
	    	$reader = new \GeoIp2\Database\Reader($db);
		}
	    else {
	    	Yii::error("Cannot find country db please fix!");
	    	return null;
	    }
	    try {
	    	$record = $reader->country($ip);
	    }
	    catch(\Exception $e) {
	    	//\Yii::error("GEOIP GEO ERROR: ip $ip not found");
	    	return '';
	    }
		$geoip = strtolower($record->country->isoCode);

		if ($geoip == 'sm')
			$geoip = 'it';

		
		return $geoip;
	}

	public static function getGeoName($ip=null) {
		if (!isset($ip)) {
			$ip = self::getIp();
		}
	    
	    $db = self::getDbName('country');
		if (!empty($db)) {
	    	$reader = new \GeoIp2\Database\Reader($db);
		}
	    else {
	    	Yii::error("Cannot find country please fix!");
	    	return null;
	    }
	    try {
	    	$record = $reader->country($ip);
	    }
	    catch(\Exception $e) {
	    	//\Yii::error("GEOIP NAME ERROR: ip $ip not found");
	    	return '';
	    }
		$geoip = strtolower($record->country->name);

		return $geoip;
	}	

	public static function getGeoCity($ip=null) {
		if (!isset($ip)) {
			$ip = self::getIp();
		}
	    
	    $db = self::getDbName('city');
	    if (!empty($db)) {
	    	$reader = new \GeoIp2\Database\Reader($db);
		}
	    else {
	    	Yii::error("Cannot find city db please fix!");
	    	return null;
	    }
	    try {
	    	$record = $reader->city($ip);
	    }
	    catch(\Exception $e) {
	    	//\Yii::error("GEOIP CITY ERROR: ip $ip not found");
	    	return '';
	    }

		return [
			'country_code' 	=> $record->country->isoCode,
			'country_name' 	=> $record->country->name,
			'region_code'	=> $record->mostSpecificSubdivision->isoCode,
			'region_name'	=> $record->mostSpecificSubdivision->name,
			'city_name'		=> $record->city->name,
			'zip'			=> $record->postal->code,
			'lat'			=> $record->location->latitude,
			'lon'			=> $record->location->longitude,
			'precision'		=> $record->location->accuracyRadius,
		];
	}	

	public static function getAsn($ip=null) {
		if (!isset($ip)) {
			$ip = self::getIp();
		}

		try {
			$db = self::getDbName('isp');
			if (empty($db)) {
				$db = self::getDbName('asn');
				if (empty($db)) {
					Yii::error("Cannot find asn db please fix!");
		    		return null;
				}
				$reader = new \GeoIp2\Database\Reader($db);
				$record = $reader->asn($ip);
			}
			else {
				$reader = new \GeoIp2\Database\Reader($db);
				$record = $reader->isp($ip);
			}			
	    }
	    catch(\Exception $e) {
	    	//\Yii::error("GEOIP ASN ERROR: ip $ip not found");
	    	return ['id'=>'','name'=>''];	
	    }
	    
		
	    $id = 'AS'.$record->autonomousSystemNumber;
	    $name = $record->autonomousSystemOrganization;
	    
	    return ['id'=>$id,'name'=>$name];
	}


	public static function isBot($ip=null) {		
		$asn = self::getAsn($ip);	    	   
		return in_array($asn['id'], self::ASN_BOT_LIST);
	}

	private static function ip_is_private ($ip) {
	    $pri_addrs = array (
	                      '10.0.0.0|10.255.255.255', // single class A network
	                      '172.16.0.0|172.31.255.255', // 16 contiguous class B network
	                      '192.168.0.0|192.168.255.255', // 256 contiguous class C network
	                      '169.254.0.0|169.254.255.255', // Link-local address also refered to as Automatic Private IP Addressing
	                      '127.0.0.0|127.255.255.255' // localhost
	                     );

	    $long_ip = ip2long ($ip);
	    if ($long_ip != -1) {

	        foreach ($pri_addrs AS $pri_addr) {
	            list ($start, $end) = explode('|', $pri_addr);

	             // IF IS PRIVATE
	             if ($long_ip >= ip2long ($start) && $long_ip <= ip2long ($end)) {
	                 return true;
	             }
	        }
	    }

	    return false;
	}

	public static function getDevice($ua=null) {
		if (!isset($ua)) {
			$ua = isset($_SERVER['HTTP_USER_AGENT'])?$_SERVER['HTTP_USER_AGENT']:'';
		}
		$mobiledetect = new MobileDetect(null,$ua);
        $device = '';
        $bot = false;
        if ($mobiledetect->isiphone()) {
            $device = 'iphone';
            $os = 'ios';
        }
        elseif ($mobiledetect->isipad()) {
            $device = 'ipad';
            $os = 'ios';
        }
        elseif ($mobiledetect->isipod()) {
            $device = 'ipod';
            $os = 'ios';
        }
        elseif ($mobiledetect->isAndroidOS()) {
            $device = 'android';    
            $os = 'android';
        }
        else {
            
        	$dd = new DeviceDetector($ua);


			// OPTIONAL: Set caching method
			// By default static cache is used, which works best within one php process (memory array caching)
			// To cache across requests use caching in files or memcache
			//$dd->setCache(new Doctrine\Common\Cache\PhpFileCache('./tmp/'));

			// OPTIONAL: If called, getBot() will only return true if a bot was detected  (speeds up detection a bit)
			$dd->discardBotInformation();

			// OPTIONAL: If called, bot detection will completely be skipped (bots will be detected as regular devices then)
			$dd->skipBotDetection();

			$dd->parse();

			if ($dd->isBot()) {
			  // handle bots,spiders,crawlers,...
			  $bot = $dd->getBot();
			} else {
			  $clientInfo = $dd->getClient(); // holds information about browser, feed reader, media player, ...			  
			  $os = $dd->getOs();
			  $os = isset($os['name'])?$os['name']:'';
			  $device = isset($clientInfo['name'])?$clientInfo['name']:'';			  
			}

        }

        return ['device' => $device, 'os' => $os, 'bot' => $bot, 'ismobile' => $mobiledetect->isMobile()];
	}

	public static function createDateRangeArray($strDateFrom,$strDateTo) {
	    // takes two dates formatted as YYYY-MM-DD and creates an
	    // inclusive array of the dates between the from and to dates.

	    // could test validity of dates here but I'm already doing
	    // that in the main script

	    $aryRange=array();

	    $iDateFrom=mktime(1,0,0,
	    	(int)substr($strDateFrom,5,2),     
	    	(int)substr($strDateFrom,8,2),
	    	(int)substr($strDateFrom,0,4)
	    	);
	    $iDateTo=mktime(1,0,0,
	    	(int)substr($strDateTo,5,2),     
	    	(int)substr($strDateTo,8,2),
	    	(int)substr($strDateTo,0,4)
	    	);

	    if ($iDateTo>=$iDateFrom)
	    {
	        array_push($aryRange,date('Y-m-d',$iDateFrom)); // first entry
	        while ($iDateFrom<$iDateTo)
	        {
	            $iDateFrom+=86400; // add 24 hours
	            array_push($aryRange,date('Y-m-d',$iDateFrom));
	        }
	    }
	    return $aryRange;
	}

	private static function getDbName($db) {
		switch(strtolower($db)) {
			case 'country':
				if (file_exists("/usr/local/share/GeoIP/GeoIP2-Country.mmdb"))
					return "/usr/local/share/GeoIP/GeoIP2-Country.mmdb";
				elseif (file_exists("/usr/local/share/GeoIP/GeoLite2-Country.mmdb"))
					return "/usr/local/share/GeoIP/GeoLite2-Country.mmdb";	
			break;			
			case 'city':
				if (file_exists("/usr/local/share/GeoIP/GeoLite2-City.mmdb"))
					return "/usr/local/share/GeoIP/GeoLite2-City.mmdb";
			break;
			case 'asn':
				if (file_exists("/usr/local/share/GeoIP/GeoLite2-ASN.mmdb"))
					return "/usr/local/share/GeoIP/GeoLite2-ASN.mmdb";
			break;
			case 'isp':
				if (file_exists("/usr/local/share/GeoIP/GeoIP2-ISP.mmdb"))
					return "/usr/local/share/GeoIP/GeoIP2-ISP.mmdb";		
			break;		
		}
		return null;
	}
}

?>