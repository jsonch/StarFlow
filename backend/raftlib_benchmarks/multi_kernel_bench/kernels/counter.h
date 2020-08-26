
#ifndef STARFLOW_KERNELS_COUNTER
#define STARFLOW_KERNELS_COUNTER

namespace starflow {
	namespace kernels {
		template<typename T>
		class Counter : public raft::kernel
		{
		public:
			Counter() : raft::kernel()
			{
				input.template add_port<T>("in");
				output.add_port<unsigned long long>("out");
			}

			raft::kstatus run() override
			{
				T t;
				input["in"].pop(t);

				auto out(output["out"].template allocate_s<unsigned long long>());
				*out = ++_counter;

				return(raft::proceed);
			}

		private:
			unsigned long long _counter = 0;
		};
	}
}


#endif