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
Date                   :=2012-10-29
CodeLitePath           :="d:\CodeLite"
LinkerName             :=g++
SharedObjectLinkerName :=g++ -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.o.i
DebugSwitch            :=-gstab
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
LinkOptions            :=  -ggdb -Wl,-pie -pedantic
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)psapi 
ArLibs                 :=  "psapi" 
LibPath                := $(LibraryPathSwitch). 

##
## Common variables
## AR, CXX, CC, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := ar rcus
CXX      := g++
CC       := gcc
CXXFLAGS :=  -ggdb -Wall -pedantic $(Preprocessors)
CFLAGS   :=  -ggdb -Wall -pedantic $(Preprocessors)


##
## User defined environment variables
##
CodeLiteDir:=d:\CodeLite
UNIT_TEST_PP_SRC_DIR:=e:\UnitTest++-1.3
WXWIN:=e:\wxWidgets-2.8.12
PATH:=$(WXWIN)\lib\gcc_dll;$(PATH)
WXCFG:=gcc_dll\mswu
Objects=$(IntermediateDirectory)/knockout$(ObjectSuffix) $(IntermediateDirectory)/scit$(ObjectSuffix) 

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
$(IntermediateDirectory)/knockout$(ObjectSuffix): knockout.cpp $(IntermediateDirectory)/knockout$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "D:/prj/cl workspace/knockout/knockout.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/knockout$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/knockout$(DependSuffix): knockout.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/knockout$(ObjectSuffix) -MF$(IntermediateDirectory)/knockout$(DependSuffix) -MM "D:/prj/cl workspace/knockout/knockout.cpp"

$(IntermediateDirectory)/knockout$(PreprocessSuffix): knockout.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/knockout$(PreprocessSuffix) "D:/prj/cl workspace/knockout/knockout.cpp"

$(IntermediateDirectory)/scit$(ObjectSuffix): scit.c $(IntermediateDirectory)/scit$(DependSuffix)
	$(CC) $(SourceSwitch) "D:/prj/cl workspace/knockout/scit.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/scit$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/scit$(DependSuffix): scit.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/scit$(ObjectSuffix) -MF$(IntermediateDirectory)/scit$(DependSuffix) -MM "D:/prj/cl workspace/knockout/scit.c"

$(IntermediateDirectory)/scit$(PreprocessSuffix): scit.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/scit$(PreprocessSuffix) "D:/prj/cl workspace/knockout/scit.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) $(IntermediateDirectory)/knockout$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/knockout$(DependSuffix)
	$(RM) $(IntermediateDirectory)/knockout$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/scit$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/scit$(DependSuffix)
	$(RM) $(IntermediateDirectory)/scit$(PreprocessSuffix)
	$(RM) $(OutputFile)
	$(RM) $(OutputFile).exe
	$(RM) "D:\prj\cl workspace\.build-debug\knockout"


