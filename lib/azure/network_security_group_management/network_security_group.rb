module Azure
  module NetworkSecurityGroupManagement
    class NetworkSecurityGroup
      attr_accessor :name, :label, :location, :state, :rules

      def initialize
        yield self if block_given?
      end
    end
  end
end
