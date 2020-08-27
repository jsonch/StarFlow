
#ifndef STARFLOW_KERNELS_PRINTER
#define STARFLOW_KERNELS_PRINTER

#include <iostream>

namespace starflow {
	namespace kernels {
		template<typename T>
		class Printer : public raft::kernel
		{
		public:
			explicit Printer(std::ostream& os = std::cout, bool endl = true, bool forward = false)
				: raft::kernel(),
				  _os(os),
				  _endl(endl),
				  _forward(forward)
			{
				input.template add_port<T>("in");
				if (_forward)
					output.template add_port<T>("out");
			}

			raft::kstatus run() override
			{
				T t{};
				input["in"].pop(t);
				_os << t << (_endl ? '\n' : '\0');

				if (_forward) {
					auto out(output["out"].template allocate_s<T>());
					*out = t;
				}

				return (raft::proceed);
			}

		private:
			std::ostream& _os;
			bool _endl;
			bool _forward;
		};
	}
}

#endif
