
#ifndef STARFLOW_KERNELS_REDIS_FLOW_SUBSCRIBER
#define STARFLOW_KERNELS_REDIS_FLOW_SUBSCRIBER

#include "../redis_flow_subscriber.h"
#include <utility>

namespace starflow {
	namespace kernels {
		class RedisFlowSubscriber : public raft::kernel
		{
		public:

			using output_t = std::pair<starflow::FlowTable::key_t, starflow::Flow>;

			RedisFlowSubscriber(const std::string& host, unsigned port, const std::string& topic)
				: _redis_subscriber(host, port, topic,
									[this](starflow::FlowTable::key_t k, starflow::Flow f) {
										_new_flow(k, f);
									})
			{
				output.add_port<output_t>("out");
			}

			void _new_flow(starflow::FlowTable::key_t k, starflow::Flow f)
			{
				auto out(output["out"].allocate_s<output_t>());
				*out = std::make_pair(k, f);
			}

			raft::kstatus run() override
			{
				_redis_subscriber();
				return(raft::proceed);
			}

		private:
			starflow::RedisFlowSubscriber _redis_subscriber;
		};
	}
}

#endif
