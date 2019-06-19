#ifndef FORMATSTRINGHANDLER_H
#define FORMATSTRINGHANDLER_H

using namespace clang;

struct FormatStringHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");

        if (ArgDataflow) {
            auto fnname = get_containing_function_name(Result, *callExpr);

            // only instrument this printf with a read disclosure
            // if it's in the body of a function that is on our whitelist
            if (fninstr(fnname)) {
                debug(INJECT) << "FormatStringHandler: Containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            }
            else {
                debug(INJECT) << "FormatStringHandler: Containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }

            debug(INJECT) << "FormatStringHandler handle: ok to instrument " << fnname.second << "\n";
        }
        
        LExpr addend = LDecimal(0);
        LavaASTLoc ast_loc = GetASTLoc(sm, callExpr);
        if (LavaAction == LavaQueries)  {
            addend = LavaAtpQuery(ast_loc,
                                AttackPoint::FORMAT_STRING);
            num_atp_queries++;
            Mod.Add(addend, nullptr);
        } else if (LavaAction == LavaInjectBugs) {
            
            const std::vector<const Bug*> &injectable_bugs =
                            map_get_default(bugs_with_atp_at,
                                    std::make_pair(ast_loc, AttackPoint::FORMAT_STRING));
            if (!injectable_bugs.empty()) {
                Mod.Change(callExpr).InsertBefore("if " + Test(injectable_bugs.front()).render() + "{ printf(\"%d%d%d%d\"); } else {");
                Mod.InsertAfterEnd("}");
            } else {
                debug(INJECT) << "AST_LOC EMPTY" << ast_loc << "\n";
            }
        }
    }
};


#endif
