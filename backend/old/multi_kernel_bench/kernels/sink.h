
#ifndef STARFLOW_KERNELS_SINK
#define STARFLOW_KERNELS_SINK


namespace starflow {
	namespace kernels {
		template<typename T>
		class Sink : public raft::kernel
		{
		public:
			explicit Sink()
				: raft::kernel()
			{
				input.template add_port<T>("in");
			}

			raft::kstatus run() override
			{
//				T t{};
//				input["in"].pop(t);

				return (raft::proceed);
			}
		};
	}
}

#endif
