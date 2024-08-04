package hook_func

func init() {
	RegisterInitialFunc("check bind port", checkBindPortLegal)
}
