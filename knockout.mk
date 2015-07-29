##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=knockout
ConfigurationName      :=Debug
WorkspacePath          := "D:\prj\cl workspace"
ProjectPath            := "D:\prj\cl workspace\knockout"
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=s0ck3t
Date                   :=2013-01-12
CodeLitePath           :="d:\CodeLite"
LinkerName             :=gcc
SharedObjectLinkerName :=gcc -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.o.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E 
ObjectsFileList        :="D:\prj\cl workspace\knockout\knockout.txt"
PCHCompileFlags        :=
MakeDirCommand         :=makedir
LinkOptions            :=  -Wl,-pie -O3
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)psapi $(LibrarySwitch)imagehlp 
ArLibs                 :=  "psapi" "imagehlp" 
LibPath                := $(LibraryPathSwitch). 

##
## Common variables
## AR, CXX, CC, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := ar rcus
CXX      := gcc
CC       := gcc
CXXFLAGS :=  -Wl,-pie -O3 $(Preprocessors)
CFLAGS   :=  -Wl,-pie -O3 $(Preprocessors)


##
## User defined environment variables
##
CodeLiteDir:=d:\CodeLite
UNIT_TEST_PP_SRC_DIR:=e:\UnitTest++-1.3
WXWIN:=e:\wxWidgets-2.8.12
PATH:=$(WXWIN)\lib\gcc_dll;$(PATH)
WXCFG:=gcc_dll\mswu
Objects=$(IntermediateDirectory)/knockout$(ObjectSuffix) $(IntermediateDirectory)/libdasm-beta_libdasm$(ObjectSuffix) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild
all: $(OutputFile)

$(OutputFile): $(IntermediateDirectory)/.d $(Objects) 
	@$(MakeDirCommand) $(@D)
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects) > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

$(IntermediateDirectory)/.d:
	@$(MakeDirCommand) "./Debug"

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/knockout$(ObjectSuffix): knockout.c $(IntermediateDirectory)/knockout$(DependSuffix)
	$(CC) $(SourceSwitch) "D:/prj/cl workspace/knockout/knockout.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/knockout$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/knockout$(DependSuffix): knockout.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/knockout$(ObjectSuffix) -MF$(IntermediateDirectory)/knockout$(DependSuffix) -MM "D:/prj/cl workspace/knockout/knockout.c"

$(IntermediateDirectory)/knockout$(PreprocessSuffix): knockout.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/knockout$(PreprocessSuffix) "D:/prj/cl workspace/knockout/knockout.c"

$(IntermediateDirectory)/libdasm-beta_libdasm$(ObjectSuffix): libdasm-beta/libdasm.c $(IntermediateDirectory)/libdasm-beta_libdasm$(DependSuffix)
	$(CC) $(SourceSwitch) "D:/prj/cl workspace/knockout/libdasm-beta/libdasm.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/libdasm-beta_libdasm$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/libdasm-beta_libdasm$(DependSuffix): libdasm-beta/libdasm.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/libdasm-beta_libdasm$(ObjectSuffix) -MF$(IntermediateDirectory)/libdasm-beta_libdasm$(DependSuffix) -MM "D:/prj/cl workspace/knockout/libdasm-beta/libdasm.c"

$(IntermediateDirectory)/libdasm-beta_libdasm$(PreprocessSuffix): libdasm-beta/libdasm.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/libdasm-beta_libdasm$(PreprocessSuffix) "D:/prj/cl workspace/knockout/libdasm-beta/libdasm.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) $(IntermediateDirectory)/knockout$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/knockout$(DependSuffix)
	$(RM) $(IntermediateDirectory)/knockout$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/libdasm-beta_libdasm$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/libdasm-beta_libdasm$(DependSuffix)
	$(RM) $(IntermediateDirectory)/libdasm-beta_libdasm$(PreprocessSuffix)
	$(RM) $(OutputFile)
	$(RM) $(OutputFile).exe
	$(RM) "D:\prj\cl workspace\.build-debug\knockout"


