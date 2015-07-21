require 'azure/network_security_group_management/network_security_group'
require 'azure/network_security_group_management/network_security_group_rule'

module Azure
  module NetworkSecurityGroupManagement
    module Serialization
      extend Azure::Core::Utility

      def self.create_nsg_to_xml(params)
        Nokogiri::XML::Builder.new do |xml|
          xml.NetworkSecurityGroup(
            'xmlns'   => 'http://schemas.microsoft.com/windowsazure',
            'xmlns:i' => 'http://www.w3.org/2001/XMLSchema-instance'
          ) do
            xml.Name params[:name]
            xml.Label params[:label]
            xml.Location params[:location]
          end
        end.doc.to_xml
      end

      def self.nsg_list_from_xml(respXML)
        nsgs = []

        respXML.css('NetworkSecurityGroups NetworkSecurityGroup').each do |group|
          sg = NetworkSecurityGroup.new do |klass|
            klass.name      = xml_content(group, 'Name')
            klass.label     = xml_content(group, 'Label')
            klass.location  = xml_content(group, 'Location')
            klass.state     = xml_content(group, 'State')
          end

          nsgs << sg
        end

        nsgs
      end

      def self.nsg_from_xml(respXML)
        group = respXML.at_css('NetworkSecurityGroup')

        NetworkSecurityGroup.new do |klass|
          klass.name      = xml_content(group, 'Name')
          klass.label     = xml_content(group, 'Label')
          klass.location  = xml_content(group, 'Location')
          klass.state     = xml_content(group, 'State')
          klass.rules     = []

          respXML.css('NetworkSecurityGroup Rules Rule').each do |r|
            klass.rules << NetworkSecurityGroupRule.new do |rklass|
              rklass.name                       = xml_content(r, 'Name')
              rklass.type                       = xml_content(r, 'Type')
              rklass.priority                   = xml_content(r, 'Priority')
              rklass.action                     = xml_content(r, 'Action')
              rklass.source_address_prefix      = xml_content(r, 'SourceAddressPrefix')
              rklass.source_port_range          = xml_content(r, 'SourcePortRange')
              rklass.destination_address_prefix = xml_content(r, 'DestinationAddressPrefix')
              rklass.destination_port_range     = xml_content(r, 'DestinationPortRange')
              rklass.protocol                   = xml_content(r, 'Protocol')
              rklass.state                      = xml_content(r, 'State')

              default = xml_content(r, 'IsDefault')
              rklass.is_default = default.nil? || default.empty? ? false : default
            end
          end
        end
      end

      def self.nsg_rule_to_xml(params)
        Nokogiri::XML::Builder.new do |xml|
          xml.Rule(
            'xmlns'   => 'http://schemas.microsoft.com/windowsazure',
            'xmlns:i' => 'http://www.w3.org/2001/XMLSchema-instance'
          ) do
            xml.Name                      params[:name]
            xml.Type                      rule_type_from_sym(params[:type])
            xml.Priority                  params[:priority].to_i
            xml.Action                    rule_action_from_sym(params[:action])
            xml.SourceAddressPrefix       rule_addr(params[:source_address_prefix])
            xml.SourcePortRange           rule_addr(params[:source_port_range])
            xml.DestinationAddressPrefix  rule_addr(params[:destination_address_prefix])
            xml.DestinationPortRange      rule_addr(params[:destination_port_range])
            xml.Protocol                  rule_protocol(params[:protocol])
          end
        end.doc.to_xml
      end

      def self.add_nsg_to_role_to_xml(nsg_name)
        Nokogiri::XML::Builder.new do |xml|
          xml.NetworkSecurityGroup(
            'xmlns'   => 'http://schemas.microsoft.com/windowsazure',
            'xmlns:i' => 'http://www.w3.org/2001/XMLSchema-instance'
          ) do
            xml.Name nsg_name
          end
        end.doc.to_xml
      end

      def self.get_nsg_from_role_from_xml(respXML)
        group = respXML.at_css('NetworkSecurityGroup')

        NetworkSecurityGroup.new do |klass|
          klass.name      = xml_content(group, 'Name')
          klass.state     = xml_content(group, 'State')
        end
      end

      private

      def self.rule_type_from_sym(sym)
        case sym
        when :outbound
          'Outbound'
        when :inbound
          'Inbound'
        end
      end

      def self.rule_action_from_sym(sym)
        case sym
        when :allow
          'Allow'
        when :deny
          'Deny'
        when :any
          '*'
        end
      end


      def self.rule_addr(val)
        v = val.to_s
        case v
        when nil, '', '*'
          '*'
        else
          v
        end
      end

      def self.rule_protocol(proto)
        case protocol
        when :tcp
          'TCP'
        when :udp
          'UDP'
        else
          '*'
        end
      end

    end
  end
end