{% if helpers.exists('OPNsense.ladon.general.enabled') and OPNsense.ladon.general.enabled == '1' %}
ladon_enable="YES"
{% else %}
ladon_enable="NO"
{% endif %}
