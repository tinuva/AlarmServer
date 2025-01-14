This is still beta software.

The ssl certificates that are provided are intended for demo purposes only.  
Please use openssl to generate your own. A quick HOWTO is below.

As with any project documentation is key, there is plenty more to go in here and
it will hopefully be soon!

Config:
Please see the alarmserver-example.cfg and rename to alarmserver.cfg and
customize to requirements.


OpenSSL Certificate Howto
-------------------

To generate a self signed cert issue the following in a command prompt:
`openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt`

Openssl will ask you some questions. The only semi-important one is the 'common name' field.
You want this set to your servers fqdn. IE alarmserver.example.com. 

If you have a real ssl cert from a certificate authority and it has intermediate certs then you'll need to bundle them all up or the webbrowser will complain about it not being a valid cert. To bundle the certs use cat to include your cert, then the intermediates (ie cat mycert.crt > combined.crt; cat intermediates.crt >> combined.crt) 


Dependencies:
-------------

On windows, pyOpenSSL is required.
http://pypi.python.org/pypi/pyOpenSSL


REST API Info
-------------

*/api*

* Returns a JSON dump of all currently known states
 
*/api/alarm/arm*

* Quick arm

*/api/alarm/armwithcode?alarmcode=1111*

* Arm with a code
  * Required param = **alarmcode**

*/api/alarm/stayarm*

* Stay arm, no code needed

*/api/alarm/disarm*

* Disarm system
   * Optional param = **alarmcode**
   * If alarmcode param is missing the config file value is used instead

*/api/pgm*

* Activate a PGM output:
  * Required param = **pgmnum**
  * Required param = **alarmcode**

*/api/refresh*

* Refresh data from alarm panel

*/api/config/eventtimeago* 

* Returns status of eventtimeago from the config file

*/api/alarm/bypass?zone=1*

* Toggle zone 1 bypass
  * Required param = **zone**  