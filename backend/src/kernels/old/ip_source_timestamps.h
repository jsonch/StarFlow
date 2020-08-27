
#ifndef STARFLOW_KERNELS_IP_SOURCE_TIMESTAMPS
#define STARFLOW_KERNELS_IP_SOURCE_TIMESTAMPS

#include <raft>
#include <sstream>
#include <ostream>
#include "../flow.h"
#include "../flow_table.h"

namespace starflow {
	namespace kernels {
		class IPSourceTimestamps : public raft::kernel
		{
		public:

			using input_t  = std::pair<starflow::FlowTable::key_t, starflow::Flow>;
			using output_t = std::pair<unsigned, std::list<std::chrono::microseconds>>;

			IPSourceTimestamps() : raft::kernel()
			{
				input.add_port<input_t>("in");
				output.add_port<output_t>("out");
			}

			raft::kstatus run() override
			{
				input_t flow;
				input["in"].pop(flow);

				std::list<std::chrono::microseconds> timestamps;

				for (auto& packet : flow.second.packets())
					timestamps.push_back(packet.ts);

				auto out(output["out"].allocate_s<output_t>());
				auto pair = std::make_pair(flow.first.ip_src, timestamps);
				*out = pair;

				std::cout << to_string(pair) << std::endl;

				return(raft::proceed);
			}

			static std::string to_string(const output_t& p)
			{
				std::stringstream ss;
				ss << FlowTable::uint32_ip_addr_to_str(p.first) << ":";

				for (auto& ts : p.second)
					ss << " " << ts.count();

				return ss.str();
			}
		};
	}
}

#endif
