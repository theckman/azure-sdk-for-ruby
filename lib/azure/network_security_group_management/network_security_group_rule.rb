module Azure
  module NetworkSecurityGroupManagement
    class NetworkSecurityGroupRule
      attr_accessor :name, :type, :priority, :action
      attr_accessor :source_address_prefix, :source_port_range
      attr_accessor :destination_address_prefix, :destination_port_range
      attr_accessor :protocol, :state, :is_default

      def initialize
        yield self if block_given?
      end

      def is_default?
        is_default
      end
    end
  end
end
